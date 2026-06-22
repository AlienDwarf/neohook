#![cfg(windows)]

//! Hook `IDirect3DDevice9::EndScene` and draw an overlay from inside the detour.
//!
//! `EndScene` runs once per frame, so it is the perfect place to draw on top.
//! Hook off -> black window; hook on -> red square.
//!
//! `EndScene` is virtual COM method 42, so this is a VTable hook
//! ([`DetourTransaction::attach_vtable`]). Finding the function is the "naive"
//! way - read the vtable pointer straight out of the COM object; no export
//! lookup is involved. Direct3D 9 is not in `windows-sys`, so `d3d9.dll` is
//! loaded at runtime and the object layout is read by hand.

use neohook::DetourTransaction;
use std::error::Error;
use std::ffi::c_void;
use std::sync::OnceLock;

use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress, LoadLibraryW};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, MSG, PM_REMOVE, PeekMessageW,
    PostQuitMessage, RegisterClassW, SW_SHOW, ShowWindow, TranslateMessage, WM_DESTROY, WM_QUIT,
    WNDCLASSW, WS_OVERLAPPEDWINDOW,
};

// --- Minimal Direct3D 9 definitions (not provided by windows-sys) ---

const D3D_SDK_VERSION: u32 = 32;
const D3DADAPTER_DEFAULT: u32 = 0;
const D3DDEVTYPE_HAL: u32 = 1;
const D3DDEVTYPE_NULLREF: u32 = 4;
const D3DCREATE_SOFTWARE_VERTEXPROCESSING: u32 = 0x20;
const D3DCREATE_HARDWARE_VERTEXPROCESSING: u32 = 0x40;
const D3DSWAPEFFECT_DISCARD: u32 = 1;
const D3DFMT_X8R8G8B8: u32 = 22;
const D3DCLEAR_TARGET: u32 = 0x1;
/// Opaque red in D3DCOLOR (ARGB) form.
const RED: u32 = 0xFFFF_0000;
const WIN_SIZE: i32 = 400;

/// Vtable slots (see any IDirect3DDevice9 layout reference).
const CREATE_DEVICE_SLOT: usize = 16; // IDirect3D9::CreateDevice
const PRESENT_SLOT: usize = 17; // IDirect3DDevice9::Present
const BEGIN_SCENE_SLOT: usize = 41;
const END_SCENE_SLOT: usize = 42; // the famous "index 42"
const CLEAR_SLOT: usize = 43;
const RELEASE_SLOT: usize = 2; // IUnknown::Release

#[repr(C)]
struct D3dPresentParameters {
    back_buffer_width: u32,
    back_buffer_height: u32,
    back_buffer_format: u32,
    back_buffer_count: u32,
    multi_sample_type: u32,
    multi_sample_quality: u32,
    swap_effect: u32,
    h_device_window: HWND,
    windowed: i32,
    enable_auto_depth_stencil: i32,
    auto_depth_stencil_format: u32,
    flags: u32,
    full_screen_refresh_rate_in_hz: u32,
    presentation_interval: u32,
}

/// `RECT`-like rectangle used by `Clear` (left, top, right, bottom).
#[repr(C)]
struct D3dRect {
    x1: i32,
    y1: i32,
    x2: i32,
    y2: i32,
}

type Direct3DCreate9Fn = unsafe extern "system" fn(u32) -> *mut c_void;
type CreateDeviceFn = unsafe extern "system" fn(
    *mut c_void, // this (IDirect3D9*)
    u32,         // Adapter
    u32,         // DeviceType
    HWND,        // hFocusWindow
    u32,         // BehaviorFlags
    *mut D3dPresentParameters,
    *mut *mut c_void, // ppReturnedDeviceInterface
) -> i32;
/// `HRESULT IDirect3DDevice9::BeginScene/EndScene(this)`.
type SceneFn = unsafe extern "system" fn(*mut c_void) -> i32;
/// `HRESULT Clear(this, Count, pRects, Flags, Color, Z, Stencil)`.
type ClearFn =
    unsafe extern "system" fn(*mut c_void, u32, *const D3dRect, u32, u32, f32, u32) -> i32;
/// `HRESULT Present(this, pSrcRect, pDstRect, hDestWindow, pDirtyRegion)`.
type PresentFn = unsafe extern "system" fn(
    *mut c_void,
    *const c_void,
    *const c_void,
    HWND,
    *const c_void,
) -> i32;
type ReleaseFn = unsafe extern "system" fn(*mut c_void) -> u32;

/// The original `EndScene` returned by `attach_vtable`, used to finalize frames.
static ORIGINAL_END_SCENE: OnceLock<SceneFn> = OnceLock::new();

/// Reads the COM object's vtable (the first pointer-sized field).
unsafe fn vtable_of(obj: *mut c_void) -> *mut *mut u8 {
    unsafe { *(obj as *const *mut *mut u8) }
}

unsafe fn slot_fn<T>(obj: *mut c_void, index: usize) -> T {
    unsafe { std::mem::transmute_copy(&*vtable_of(obj).add(index)) }
}

/// Detour: clear a centered rectangle to red (the overlay), then run the real
/// `EndScene` to finalize the frame.
unsafe extern "system" fn end_scene_detour(this: *mut c_void) -> i32 {
    unsafe {
        let clear: ClearFn = slot_fn(this, CLEAR_SLOT);
        let rect = D3dRect {
            x1: WIN_SIZE / 4,
            y1: WIN_SIZE / 4,
            x2: WIN_SIZE * 3 / 4,
            y2: WIN_SIZE * 3 / 4,
        };
        clear(this, 1, &rect, D3DCLEAR_TARGET, RED, 1.0, 0);
        ORIGINAL_END_SCENE.get().expect("original EndScene set")(this)
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
        // --- Resolve Direct3DCreate9 and create the D3D9 object ---
        let d3d9_dll = LoadLibraryW(wide("d3d9.dll").as_ptr());
        if d3d9_dll.is_null() {
            println!("skipped: d3d9.dll not available");
            return Ok(());
        }
        let create_ptr = match GetProcAddress(d3d9_dll, c"Direct3DCreate9".as_ptr() as *const u8) {
            Some(p) => p,
            None => {
                println!("skipped: Direct3DCreate9 not found");
                return Ok(());
            }
        };
        let direct3d_create9: Direct3DCreate9Fn = std::mem::transmute(create_ptr);
        let d3d9 = direct3d_create9(D3D_SDK_VERSION);
        if d3d9.is_null() {
            println!("skipped: Direct3DCreate9 returned null");
            return Ok(());
        }

        // --- Create the window the device renders into ---
        let hinstance = GetModuleHandleW(std::ptr::null());
        let class_name = wide("NeoHookD3D9Demo");
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
            wide("neohook - d3d9 hook (red square is drawn by the hook)").as_ptr(),
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

        let mut pp = D3dPresentParameters {
            back_buffer_width: WIN_SIZE as u32,
            back_buffer_height: WIN_SIZE as u32,
            back_buffer_format: D3DFMT_X8R8G8B8,
            back_buffer_count: 1,
            multi_sample_type: 0,
            multi_sample_quality: 0,
            swap_effect: D3DSWAPEFFECT_DISCARD,
            h_device_window: hwnd,
            windowed: 1,
            enable_auto_depth_stencil: 0,
            auto_depth_stencil_format: 0,
            flags: 0,
            full_screen_refresh_rate_in_hz: 0,
            presentation_interval: 0,
        };

        // --- Create the device: HAL (renders on a GPU) or NULLREF fallback ---
        let create_device: CreateDeviceFn = slot_fn(d3d9, CREATE_DEVICE_SLOT);
        let mut device: *mut c_void = std::ptr::null_mut();
        let mut hr = create_device(
            d3d9,
            D3DADAPTER_DEFAULT,
            D3DDEVTYPE_HAL,
            hwnd,
            D3DCREATE_HARDWARE_VERTEXPROCESSING,
            &mut pp,
            &mut device,
        );
        if hr < 0 || device.is_null() {
            hr = create_device(
                d3d9,
                D3DADAPTER_DEFAULT,
                D3DDEVTYPE_NULLREF,
                hwnd,
                D3DCREATE_SOFTWARE_VERTEXPROCESSING,
                &mut pp,
                &mut device,
            );
            println!("note: no GPU device, using NULLREF (window stays black)");
        }
        if hr < 0 || device.is_null() {
            println!("skipped: CreateDevice failed (hr = {hr:#x})");
            slot_fn::<ReleaseFn>(d3d9, RELEASE_SLOT)(d3d9);
            return Ok(());
        }

        // --- Hook EndScene by patching its vtable slot ---
        let vtable = vtable_of(device);
        let mut tx = DetourTransaction::begin();
        let original = tx.attach_vtable(vtable, END_SCENE_SLOT, end_scene_detour as *const u8)?;
        let _hooks = tx.commit()?;
        let _ = ORIGINAL_END_SCENE.set(std::mem::transmute::<*mut u8, SceneFn>(original));
        println!("hooked IDirect3DDevice9::EndScene - close the window to exit");

        // --- Render loop: clear black, draw the (empty) scene, present. The red
        //     square is added inside the EndScene detour. ---
        let clear: ClearFn = slot_fn(device, CLEAR_SLOT);
        let begin_scene: SceneFn = slot_fn(device, BEGIN_SCENE_SLOT);
        let present: PresentFn = slot_fn(device, PRESENT_SLOT);

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
            clear(
                device,
                0,
                std::ptr::null(),
                D3DCLEAR_TARGET,
                0xFF00_0000,
                1.0,
                0,
            );
            begin_scene(device);
            // EndScene dispatches through the hooked vtable slot.
            let end_scene: SceneFn = std::mem::transmute(*vtable.add(END_SCENE_SLOT));
            end_scene(device);
            present(
                device,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null(),
            );
        }

        // --- Tear down: RAII restores EndScene, then release COM objects ---
        drop(_hooks);
        slot_fn::<ReleaseFn>(device, RELEASE_SLOT)(device);
        slot_fn::<ReleaseFn>(d3d9, RELEASE_SLOT)(d3d9);
        DestroyWindow(hwnd);
    }

    Ok(())
}
