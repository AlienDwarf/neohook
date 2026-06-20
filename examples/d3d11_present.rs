#![cfg(windows)]

//! Hook `IDXGISwapChain::Present` and draw an overlay from inside the detour.

use neohook::DetourTransaction;
use std::error::Error;
use std::ffi::c_void;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicPtr, Ordering};

use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress, LoadLibraryW};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, MSG, PM_REMOVE, PeekMessageW,
    PostQuitMessage, RegisterClassW, SW_SHOW, ShowWindow, TranslateMessage, WM_DESTROY, WM_QUIT,
    WNDCLASSW, WS_OVERLAPPEDWINDOW,
};
use windows_sys::core::GUID;

const D3D_DRIVER_TYPE_WARP: u32 = 5;
const D3D11_SDK_VERSION: u32 = 7;
const DXGI_FORMAT_R8G8B8A8_UNORM: u32 = 28;
const DXGI_USAGE_RENDER_TARGET_OUTPUT: u32 = 0x20;
const DXGI_SWAP_EFFECT_DISCARD: u32 = 0;
const WIN_SIZE: i32 = 400;

/// `IID_ID3D11Texture2D` - the back buffer's interface, needed by `GetBuffer`.
const IID_ID3D11TEXTURE2D: GUID = GUID {
    data1: 0x6f15_aaf2,
    data2: 0xd208,
    data3: 0x4e89,
    data4: [0x9a, 0xb4, 0x48, 0x95, 0x35, 0xd3, 0x4f, 0x9c],
};
/// `IID_ID3D11DeviceContext1` - the 11.1 context that exposes `ClearView`.
const IID_ID3D11DEVICECONTEXT1: GUID = GUID {
    data1: 0xbb2c_6faa,
    data2: 0xb5fb,
    data3: 0x4082,
    data4: [0x8e, 0x6b, 0x38, 0x8b, 0x8c, 0xfa, 0x90, 0xe1],
};

// Vtable slots used below (see the IDXGISwapChain / ID3D11Device /
// ID3D11DeviceContext[1] layouts).
const QUERY_INTERFACE_SLOT: usize = 0; // IUnknown::QueryInterface
const RELEASE_SLOT: usize = 2; // IUnknown::Release
const PRESENT_SLOT: usize = 8; // IDXGISwapChain::Present
/// Number of methods in the IDXGISwapChain vtable (IUnknown 3 + IDXGIObject 4 +
/// IDXGIDeviceSubObject 1 + IDXGISwapChain 10) - the slice neohook clones.
const SWAPCHAIN_VTABLE_LEN: usize = 18;
const GET_BUFFER_SLOT: usize = 9; // IDXGISwapChain::GetBuffer
const CREATE_RTV_SLOT: usize = 9; // ID3D11Device::CreateRenderTargetView
const CLEAR_RTV_SLOT: usize = 50; // ID3D11DeviceContext::ClearRenderTargetView
const CLEAR_VIEW_SLOT: usize = 132; // ID3D11DeviceContext1::ClearView

#[repr(C)]
struct DxgiRational {
    numerator: u32,
    denominator: u32,
}
#[repr(C)]
struct DxgiModeDesc {
    width: u32,
    height: u32,
    refresh_rate: DxgiRational,
    format: u32,
    scanline_ordering: u32,
    scaling: u32,
}
#[repr(C)]
struct DxgiSampleDesc {
    count: u32,
    quality: u32,
}
#[repr(C)]
struct DxgiSwapChainDesc {
    buffer_desc: DxgiModeDesc,
    sample_desc: DxgiSampleDesc,
    buffer_usage: u32,
    buffer_count: u32,
    output_window: HWND,
    windowed: i32,
    swap_effect: u32,
    flags: u32,
}

#[repr(C)]
struct D3d11Rect {
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
}

type D3d11CreateFn = unsafe extern "system" fn(
    *mut c_void, // pAdapter
    u32,         // DriverType
    *mut c_void, // Software
    u32,         // Flags
    *const u32,  // pFeatureLevels
    u32,         // FeatureLevels
    u32,         // SDKVersion
    *const DxgiSwapChainDesc,
    *mut *mut c_void, // ppSwapChain
    *mut *mut c_void, // ppDevice
    *mut u32,         // pFeatureLevel
    *mut *mut c_void, // ppImmediateContext
) -> i32;

/// `HRESULT IDXGISwapChain::Present(this, SyncInterval, Flags)`.
type PresentFn = unsafe extern "system" fn(*mut c_void, u32, u32) -> i32;
/// `HRESULT GetBuffer(this, Buffer, riid, ppSurface)`.
type GetBufferFn =
    unsafe extern "system" fn(*mut c_void, u32, *const GUID, *mut *mut c_void) -> i32;
/// `HRESULT QueryInterface(this, riid, ppvObject)`.
type QueryInterfaceFn =
    unsafe extern "system" fn(*mut c_void, *const GUID, *mut *mut c_void) -> i32;
/// `HRESULT CreateRenderTargetView(this, pResource, pDesc, ppRTV)`.
type CreateRtvFn =
    unsafe extern "system" fn(*mut c_void, *mut c_void, *const c_void, *mut *mut c_void) -> i32;
/// `void ClearRenderTargetView(this, pRTV, ColorRGBA[4])`.
type ClearRtvFn = unsafe extern "system" fn(*mut c_void, *mut c_void, *const f32);
/// `void ClearView(this, pView, Color[4], pRect, NumRects)`.
type ClearViewFn =
    unsafe extern "system" fn(*mut c_void, *mut c_void, *const f32, *const D3d11Rect, u32);
type ReleaseFn = unsafe extern "system" fn(*mut c_void) -> u32;

static ORIGINAL_PRESENT: OnceLock<PresentFn> = OnceLock::new();
/// 11.1 context + render target view the detour draws through.
static CTX1: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static RTV: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

/// Reads the COM object's vtable (the first pointer-sized field).
unsafe fn vtable_of(obj: *mut c_void) -> *mut *mut u8 {
    unsafe { *(obj as *const *mut *mut u8) }
}

unsafe fn slot_fn<T>(obj: *mut c_void, index: usize) -> T {
    unsafe { std::mem::transmute_copy(&*vtable_of(obj).add(index)) }
}

/// Detour: fill a centered rectangle with red (the overlay), then run the real
/// `Present` to put the frame on screen.
unsafe extern "system" fn present_detour(this: *mut c_void, sync: u32, flags: u32) -> i32 {
    unsafe {
        let ctx1 = CTX1.load(Ordering::Relaxed);
        let rtv = RTV.load(Ordering::Relaxed);
        if !ctx1.is_null() && !rtv.is_null() {
            let clear_view: ClearViewFn = slot_fn(ctx1, CLEAR_VIEW_SLOT);
            let red = [1.0_f32, 0.0, 0.0, 1.0];
            let rect = D3d11Rect {
                left: WIN_SIZE / 4,
                top: WIN_SIZE / 4,
                right: WIN_SIZE * 3 / 4,
                bottom: WIN_SIZE * 3 / 4,
            };
            clear_view(ctx1, rtv, red.as_ptr(), &rect, 1);
        }
        ORIGINAL_PRESENT.get().expect("original Present set")(this, sync, flags)
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

extern "system" fn wndproc(
    hwnd: HWND,
    msg: u32,
    w: windows_sys::Win32::Foundation::WPARAM,
    l: windows_sys::Win32::Foundation::LPARAM,
) -> windows_sys::Win32::Foundation::LRESULT {
    unsafe {
        if msg == WM_DESTROY {
            PostQuitMessage(0);
            return 0;
        }
        DefWindowProcW(hwnd, msg, w, l)
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    unsafe {
        // Resolve D3D11CreateDeviceAndSwapChain at runtim
        let d3d11 = LoadLibraryW(wide("d3d11.dll").as_ptr());
        if d3d11.is_null() {
            println!("skipped: d3d11.dll not available");
            return Ok(());
        }
        let create_ptr = match GetProcAddress(
            d3d11,
            c"D3D11CreateDeviceAndSwapChain".as_ptr() as *const u8,
        ) {
            Some(p) => p,
            None => {
                println!("skipped: D3D11CreateDeviceAndSwapChain not found");
                return Ok(());
            }
        };
        let create: D3d11CreateFn = std::mem::transmute(create_ptr);

        //Create the window
        let hinstance = GetModuleHandleW(std::ptr::null());
        let class_name = wide("NeoHookD3D11Demo");
        let wc = WNDCLASSW {
            style: 0,
            lpfnWndProc: Some(wndproc),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: hinstance,
            hIcon: std::ptr::null_mut(),
            hCursor: std::ptr::null_mut(),
            hbrBackground: std::ptr::null_mut(),
            lpszMenuName: std::ptr::null(),
            lpszClassName: class_name.as_ptr(),
        };
        RegisterClassW(&wc);
        let hwnd = CreateWindowExW(
            0,
            class_name.as_ptr(),
            wide("neohook - d3d11 hook (red square is drawn by the hook)").as_ptr(),
            WS_OVERLAPPEDWINDOW,
            100,
            100,
            WIN_SIZE,
            WIN_SIZE,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            hinstance,
            std::ptr::null(),
        );
        if hwnd.is_null() {
            println!("skipped: could not create a window");
            return Ok(());
        }

        let desc = DxgiSwapChainDesc {
            buffer_desc: DxgiModeDesc {
                width: WIN_SIZE as u32,
                height: WIN_SIZE as u32,
                refresh_rate: DxgiRational {
                    numerator: 60,
                    denominator: 1,
                },
                format: DXGI_FORMAT_R8G8B8A8_UNORM,
                scanline_ordering: 0,
                scaling: 0,
            },
            sample_desc: DxgiSampleDesc {
                count: 1,
                quality: 0,
            },
            buffer_usage: DXGI_USAGE_RENDER_TARGET_OUTPUT,
            buffer_count: 1,
            output_window: hwnd,
            windowed: 1,
            swap_effect: DXGI_SWAP_EFFECT_DISCARD,
            flags: 0,
        };

        // Create swapchain
        let mut swapchain: *mut c_void = std::ptr::null_mut();
        let mut device: *mut c_void = std::ptr::null_mut();
        let mut context: *mut c_void = std::ptr::null_mut();
        let mut feature_level: u32 = 0;
        let hr = create(
            std::ptr::null_mut(),
            D3D_DRIVER_TYPE_WARP,
            std::ptr::null_mut(),
            0,
            std::ptr::null(),
            0,
            D3D11_SDK_VERSION,
            &desc,
            &mut swapchain,
            &mut device,
            &mut feature_level,
            &mut context,
        );
        if hr < 0 || swapchain.is_null() {
            println!("skipped: WARP device/swapchain creation failed (hr = {hr:#x})");
            DestroyWindow(hwnd);
            return Ok(());
        }

        let mut backbuffer: *mut c_void = std::ptr::null_mut();
        slot_fn::<GetBufferFn>(swapchain, GET_BUFFER_SLOT)(
            swapchain,
            0,
            &IID_ID3D11TEXTURE2D,
            &mut backbuffer,
        );
        let mut rtv: *mut c_void = std::ptr::null_mut();
        slot_fn::<CreateRtvFn>(device, CREATE_RTV_SLOT)(
            device,
            backbuffer,
            std::ptr::null(),
            &mut rtv,
        );
        slot_fn::<ReleaseFn>(backbuffer, RELEASE_SLOT)(backbuffer);

        let mut context1: *mut c_void = std::ptr::null_mut();
        slot_fn::<QueryInterfaceFn>(context, QUERY_INTERFACE_SLOT)(
            context,
            &IID_ID3D11DEVICECONTEXT1,
            &mut context1,
        );
        if rtv.is_null() || context1.is_null() {
            println!("skipped: could not set up render target / 11.1 context");
            DestroyWindow(hwnd);
            return Ok(());
        }
        RTV.store(rtv, Ordering::Relaxed);
        CTX1.store(context1, Ordering::Relaxed);

        // Hook Present by cloning the swapchain's vtable, replacing the Present slot, and writing a
        // pointer to the clone back into the swapchain.
        let mut tx = DetourTransaction::begin();
        let original = tx.attach_vtable_instance(
            swapchain as *mut *mut u8,
            PRESENT_SLOT,
            SWAPCHAIN_VTABLE_LEN,
            present_detour as *const u8,
        )?;
        let _hooks = tx.commit()?;
        let _ = ORIGINAL_PRESENT.set(std::mem::transmute::<*mut u8, PresentFn>(original));
        println!("hooked IDXGISwapChain::Present - close the window to exit");

        // Render loop: only clear to black, then present
        let clear_rtv: ClearRtvFn = slot_fn(context, CLEAR_RTV_SLOT);
        ShowWindow(hwnd, SW_SHOW);
        let mut msg: MSG = std::mem::zeroed();
        'main: loop {
            while PeekMessageW(&mut msg, std::ptr::null_mut(), 0, 0, PM_REMOVE) != 0 {
                if msg.message == WM_QUIT {
                    break 'main;
                }
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
            let black = [0.0_f32, 0.0, 0.0, 1.0];
            clear_rtv(context, rtv, black.as_ptr());
            // Calling Present through the swapchain's (now cloned) vtable slot
            let present: PresentFn = slot_fn(swapchain, PRESENT_SLOT);
            present(swapchain, 1, 0);
        }

        drop(_hooks);
        let release = |obj: *mut c_void| {
            if !obj.is_null() {
                slot_fn::<ReleaseFn>(obj, RELEASE_SLOT)(obj);
            }
        };
        release(rtv);
        release(context1);
        release(swapchain);
        release(context);
        release(device);
        DestroyWindow(hwnd);
    }

    Ok(())
}
