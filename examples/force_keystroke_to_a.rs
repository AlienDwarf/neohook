#![cfg(windows)]

//! Hook the Win32 input path so that every typed character becomes `'a'`.
//!
//! This opens a small window with a multiline edit control and inline-hooks
//! `user32!GetMessageW`. The detour calls the real `GetMessageW` and, whenever
//! the message it returns is `WM_CHAR`, rewrites the character to `'a'` before
//! it reaches the edit control. So no matter which key you press, an `a` is
//! inserted.
//!
//! ## Why a custom window instead of `notepad.exe`?
//!
//! NeoHook hooks functions **in the current process**. To force this behavior in
//! a separate process like `notepad.exe`, the very same hook would have to run
//! *inside* that process, i.e. be injected as a DLL (NeoHook does not ship an
//! injector yet). On Windows 11 the bundled Notepad is also a WinUI/DirectWrite
//! app, so it does not route keystrokes through the classic `GetMessageW` +
//! edit-control path this example relies on. The hooking logic below is exactly
//! what an injected DLL would install; only the delivery differs.
//!
//! Run with: `cargo run --example force_keystroke_to_a`

use neohook::DetourTransaction;
use std::ffi::c_void;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicPtr, Ordering};

use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::SetFocus;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CW_USEDEFAULT, CreateWindowExW, DefWindowProcW, DispatchMessageW, ES_AUTOVSCROLL, ES_MULTILINE,
    GetMessageW, IDC_ARROW, LoadCursorW, MSG, MoveWindow, PostQuitMessage, RegisterClassW, SW_SHOW,
    ShowWindow, TranslateMessage, WM_CHAR, WM_CREATE, WM_DESTROY, WM_SETFOCUS, WM_SIZE, WNDCLASSW,
    WS_CHILD, WS_OVERLAPPEDWINDOW, WS_VISIBLE, WS_VSCROLL,
};

/// Signature of `GetMessageW`.
type GetMessageFn = unsafe extern "system" fn(*mut MSG, HWND, u32, u32) -> i32;

/// Trampoline to the original `GetMessageW`.
static ORIGINAL_GET_MESSAGE: OnceLock<GetMessageFn> = OnceLock::new();

/// Handle of the child edit control (set from the window procedure).
static EDIT: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Detour for `GetMessageW`: forward to the original, then force every
/// character message to `'a'`.
unsafe extern "system" fn hooked_get_message(msg: *mut MSG, hwnd: HWND, min: u32, max: u32) -> i32 {
    let original = ORIGINAL_GET_MESSAGE
        .get()
        .expect("original GetMessageW set");
    let ret = unsafe { original(msg, hwnd, min, max) };

    if ret != 0 && !msg.is_null() {
        let m = unsafe { &mut *msg };
        if m.message == WM_CHAR {
            m.wParam = b'a' as WPARAM;
        }
    }

    ret
}

unsafe extern "system" fn wnd_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        WM_CREATE => {
            let edit = unsafe {
                CreateWindowExW(
                    0,
                    wide("EDIT").as_ptr(),
                    std::ptr::null(),
                    WS_CHILD
                        | WS_VISIBLE
                        | WS_VSCROLL
                        | ES_MULTILINE as u32
                        | ES_AUTOVSCROLL as u32,
                    0,
                    0,
                    0,
                    0,
                    hwnd,
                    std::ptr::null_mut(),
                    GetModuleHandleW(std::ptr::null()),
                    std::ptr::null(),
                )
            };
            EDIT.store(edit, Ordering::SeqCst);
            0
        }
        WM_SIZE => {
            let edit = EDIT.load(Ordering::SeqCst);
            if !edit.is_null() {
                let width = (lparam & 0xFFFF) as i32;
                let height = ((lparam >> 16) & 0xFFFF) as i32;
                unsafe { MoveWindow(edit, 0, 0, width, height, 1) };
            }
            0
        }
        WM_SETFOCUS => {
            let edit = EDIT.load(Ordering::SeqCst);
            if !edit.is_null() {
                unsafe { SetFocus(edit) };
            }
            0
        }
        WM_DESTROY => {
            unsafe { PostQuitMessage(0) };
            0
        }
        _ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
    }
}

fn install_hook() -> neohook::Hook {
    // Resolve the real GetMessageW inside user32 (not the import thunk).
    let user32 = unsafe { GetModuleHandleW(wide("user32.dll").as_ptr()) };
    assert!(!user32.is_null(), "user32.dll not loaded");

    let proc = unsafe { GetProcAddress(user32, c"GetMessageW".as_ptr() as *const u8) }
        .expect("GetMessageW not found");
    let target = proc as *mut u8;

    let mut tx = DetourTransaction::begin();
    tx.update_all_threads();
    let tramp = tx
        .attach(target, hooked_get_message as *const u8)
        .expect("failed to attach GetMessageW hook");
    ORIGINAL_GET_MESSAGE
        .set(unsafe { std::mem::transmute::<*mut u8, GetMessageFn>(tramp) })
        .ok();

    let mut hooks = tx.commit().expect("commit failed");
    hooks.pop().expect("one hook expected")
}

fn main() {
    let h_instance = unsafe { GetModuleHandleW(std::ptr::null()) };
    let class_name = wide("NeoHookForceA");

    let wc = WNDCLASSW {
        style: 0,
        lpfnWndProc: Some(wnd_proc),
        cbClsExtra: 0,
        cbWndExtra: 0,
        hInstance: h_instance,
        hIcon: std::ptr::null_mut(),
        hCursor: unsafe { LoadCursorW(std::ptr::null_mut(), IDC_ARROW) },
        hbrBackground: std::ptr::null_mut(),
        lpszMenuName: std::ptr::null(),
        lpszClassName: class_name.as_ptr(),
    };
    let atom = unsafe { RegisterClassW(&wc) };
    assert!(atom != 0, "RegisterClassW failed");

    let hwnd = unsafe {
        CreateWindowExW(
            0,
            class_name.as_ptr(),
            wide("NeoHook: every key becomes 'a' (close to exit)").as_ptr(),
            WS_OVERLAPPEDWINDOW | WS_VISIBLE,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            520,
            360,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            h_instance,
            std::ptr::null(),
        )
    };
    assert!(!hwnd.is_null(), "CreateWindowExW failed");
    unsafe { ShowWindow(hwnd, SW_SHOW) };

    // Install the hook and keep it alive for the lifetime of the message loop.
    let _hook = install_hook();

    println!("Type into the window: every keystroke is forced to 'a'. Close the window to exit.");

    let mut msg: MSG = unsafe { std::mem::zeroed() };
    // GetMessageW is now hooked, so each WM_CHAR is rewritten before dispatch.
    while unsafe { GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) } > 0 {
        unsafe {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
}
