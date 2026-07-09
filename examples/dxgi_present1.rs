#![cfg(windows)]

//! Hook `IDXGISwapChain1::Present1` and draw an overlay from inside the detour.
//!
//! `Present1` is the flip-model buffer swap introduced with DXGI 1.2 (Windows 8+).
//! It is the modern counterpart to `IDXGISwapChain::Present` (see
//! `d3d11_present.rs`): every rendered frame ends with a `Present1`, so a hook on
//! it runs once per frame - the natural place to draw an overlay.
//!
//! Compared to the plain `Present` example this one:
//!   * creates a **flip-model** swapchain (`DXGI_SWAP_EFFECT_FLIP_SEQUENTIAL`,
//!     two back buffers) so that `Present1` is actually valid,
//!   * `QueryInterface`s the swapchain up to `IDXGISwapChain1` to reach the
//!     newer vtable, and
//!   * hooks vtable slot 22 (`Present1`), whose signature takes an extra
//!     `DXGI_PRESENT_PARAMETERS*`.
//!
//! Hook off -> black window; hook on -> red square. The app's render loop only
//! ever clears the frame to black; the red square is drawn by the detour right
//! before it forwards to the real `Present1`.
//!
//! Run with: `cargo run --example dxgi_present1`

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
/// Flip-model swap effect (DXGI 1.2+). Required for `Present1` to be valid;
/// the old `DISCARD` effect makes `Present1` return `DXGI_ERROR_INVALID_CALL`.
const DXGI_SWAP_EFFECT_FLIP_SEQUENTIAL: u32 = 3;
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
/// `IID_IDXGISwapChain1` - the DXGI 1.2 swapchain that exposes `Present1`.
const IID_IDXGISWAPCHAIN1: GUID = GUID {
    data1: 0x790a_45f7,
    data2: 0x0d42,
    data3: 0x4876,
    data4: [0x98, 0x3a, 0x0a, 0x55, 0xcf, 0xe6, 0xf4, 0xaa],
};

// Vtable slots used below (see the IDXGISwapChain1 / ID3D11Device /
// ID3D11DeviceContext[1] layouts).
const QUERY_INTERFACE_SLOT: usize = 0; // IUnknown::QueryInterface
const RELEASE_SLOT: usize = 2; // IUnknown::Release
const PRESENT1_SLOT: usize = 22; // IDXGISwapChain1::Present1
/// Number of methods in the IDXGISwapChain1 vtable (IUnknown 3 + IDXGIObject 4 +
/// IDXGIDeviceSubObject 1 + IDXGISwapChain 10 + IDXGISwapChain1 11) - the slice
/// neohook clones.
const SWAPCHAIN1_VTABLE_LEN: usize = 29;
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

/// `DXGI_PRESENT_PARAMETERS` - passed to `Present1`. All-zero means "present the
/// whole frame" (no dirty rects, no scroll).
#[repr(C)]
struct DxgiPresentParameters {
    dirty_rects_count: u32,
    p_dirty_rects: *const c_void,
    p_scroll_rect: *const c_void,
    p_scroll_offset: *const c_void,
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

/// `HRESULT IDXGISwapChain1::Present1(this, SyncInterval, Flags, pPresentParameters)`.
type Present1Fn =
    unsafe extern "system" fn(*mut c_void, u32, u32, *const DxgiPresentParameters) -> i32;
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

static ORIGINAL_PRESENT1: OnceLock<Present1Fn> = OnceLock::new();
/// 11.1 context + the render target view for the current frame's back buffer.
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
/// `Present1` to put the frame on screen.
unsafe extern "system" fn present1_detour(
    this: *mut c_void,
    sync: u32,
    flags: u32,
    params: *const DxgiPresentParameters,
) -> i32 {
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
        ORIGINAL_PRESENT1.get().expect("original Present1 set")(this, sync, flags, params)
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
        // Resolve D3D11CreateDeviceAndSwapChain at runtime.
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

        // Create the window.
        let hinstance = GetModuleHandleW(std::ptr::null());
        let class_name = wide("NeoHookPresent1Demo");
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
            wide("neohook - Present1 hook (red square is drawn by the hook)").as_ptr(),
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

        // Flip-model swapchain: two back buffers, FLIP_SEQUENTIAL swap effect.
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
            buffer_count: 2,
            output_window: hwnd,
            windowed: 1,
            swap_effect: DXGI_SWAP_EFFECT_FLIP_SEQUENTIAL,
            flags: 0,
        };

        // Create device + flip-model swapchain.
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

        // Query the swapchain up to IDXGISwapChain1 (the interface with Present1).
        let mut swapchain1: *mut c_void = std::ptr::null_mut();
        slot_fn::<QueryInterfaceFn>(swapchain, QUERY_INTERFACE_SLOT)(
            swapchain,
            &IID_IDXGISWAPCHAIN1,
            &mut swapchain1,
        );
        if swapchain1.is_null() {
            println!("skipped: IDXGISwapChain1 not available (needs DXGI 1.2 / Windows 8+)");
            slot_fn::<ReleaseFn>(swapchain, RELEASE_SLOT)(swapchain);
            DestroyWindow(hwnd);
            return Ok(());
        }

        // 11.1 context for ClearView, used by the detour to draw the overlay.
        let mut context1: *mut c_void = std::ptr::null_mut();
        slot_fn::<QueryInterfaceFn>(context, QUERY_INTERFACE_SLOT)(
            context,
            &IID_ID3D11DEVICECONTEXT1,
            &mut context1,
        );
        if context1.is_null() {
            println!("skipped: could not obtain an ID3D11DeviceContext1");
            slot_fn::<ReleaseFn>(swapchain1, RELEASE_SLOT)(swapchain1);
            slot_fn::<ReleaseFn>(swapchain, RELEASE_SLOT)(swapchain);
            DestroyWindow(hwnd);
            return Ok(());
        }
        CTX1.store(context1, Ordering::Relaxed);

        // Hook Present1 by cloning the swapchain1 vtable, replacing the Present1
        // slot, and writing the pointer to the clone back into the object.
        let mut tx = DetourTransaction::begin();
        let original = tx.attach_vtable_instance(
            swapchain1 as *mut *mut u8,
            PRESENT1_SLOT,
            SWAPCHAIN1_VTABLE_LEN,
            present1_detour as *const u8,
        )?;
        let _hooks = tx.commit()?;
        let _ = ORIGINAL_PRESENT1.set(std::mem::transmute::<*mut u8, Present1Fn>(original));
        println!("hooked IDXGISwapChain1::Present1 - close the window to exit");

        // Render loop: fetch the current back buffer, clear it to black, then
        // Present1. Flip-model rotates back buffers, so the render target view is
        // rebuilt each frame from buffer 0. The red square is added in the detour.
        let get_buffer: GetBufferFn = slot_fn(swapchain1, GET_BUFFER_SLOT);
        let create_rtv: CreateRtvFn = slot_fn(device, CREATE_RTV_SLOT);
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

            let mut backbuffer: *mut c_void = std::ptr::null_mut();
            get_buffer(swapchain1, 0, &IID_ID3D11TEXTURE2D, &mut backbuffer);
            if backbuffer.is_null() {
                continue;
            }
            let mut rtv: *mut c_void = std::ptr::null_mut();
            create_rtv(device, backbuffer, std::ptr::null(), &mut rtv);
            slot_fn::<ReleaseFn>(backbuffer, RELEASE_SLOT)(backbuffer);
            if rtv.is_null() {
                continue;
            }
            RTV.store(rtv, Ordering::Relaxed);

            let black = [0.0_f32, 0.0, 0.0, 1.0];
            clear_rtv(context, rtv, black.as_ptr());

            // Present1 dispatches through the hooked (cloned) vtable slot.
            let params = DxgiPresentParameters {
                dirty_rects_count: 0,
                p_dirty_rects: std::ptr::null(),
                p_scroll_rect: std::ptr::null(),
                p_scroll_offset: std::ptr::null(),
            };
            let present1: Present1Fn = slot_fn(swapchain1, PRESENT1_SLOT);
            present1(swapchain1, 1, 0, &params);

            // The detour is done with this frame's RTV; drop it before releasing.
            RTV.store(std::ptr::null_mut(), Ordering::Relaxed);
            slot_fn::<ReleaseFn>(rtv, RELEASE_SLOT)(rtv);
        }

        drop(_hooks);
        let release = |obj: *mut c_void| {
            if !obj.is_null() {
                slot_fn::<ReleaseFn>(obj, RELEASE_SLOT)(obj);
            }
        };
        release(context1);
        release(swapchain1);
        release(swapchain);
        release(context);
        release(device);
        DestroyWindow(hwnd);
    }

    Ok(())
}
