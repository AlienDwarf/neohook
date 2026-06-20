#![cfg(windows)]

//! Hook OpenGL's `wglSwapBuffers` and draw an overlay from inside the detour.
//!
//! Every rendered frame ends with a buffer swap, so a hook on `wglSwapBuffers`
//! runs once per frame.
//! tthe application's own render loop only
//! ever clears the window to **black**. The red square you see is drawn by the
//! detour, right before it forwards to the real swap.
//!
//! The "naive" way to install the hook: resolve `wglSwapBuffers` yourself with
//! `GetProcAddress` and inline-hook that exact address via
//! [`DetourTransaction::attach`] - no `attach_export` convenience wrapper.
//!
//! Run with: `cargo run --example opengl_swapbuffers`

use neohook::DetourTransaction;
use std::error::Error;
use std::sync::OnceLock;

use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows_sys::Win32::Graphics::Gdi::{GetDC, HDC, ReleaseDC};
use windows_sys::Win32::Graphics::OpenGL::{
    ChoosePixelFormat, PFD_DOUBLEBUFFER, PFD_DRAW_TO_WINDOW, PFD_MAIN_PLANE, PFD_SUPPORT_OPENGL,
    PFD_TYPE_RGBA, PIXELFORMATDESCRIPTOR, SetPixelFormat, glClear, glClearColor, glColor3f,
    glRectf, glViewport, wglCreateContext, wglDeleteContext, wglMakeCurrent,
};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, MSG, PM_REMOVE, PeekMessageW,
    PostQuitMessage, RegisterClassW, SW_SHOW, ShowWindow, TranslateMessage, WM_DESTROY, WM_QUIT,
    WNDCLASSW, WS_OVERLAPPEDWINDOW,
};

const GL_COLOR_BUFFER_BIT: u32 = 0x0000_4000;
const WIN_SIZE: i32 = 400;

/// `BOOL wglSwapBuffers(HDC)`.
type WglSwapBuffersFn = unsafe extern "system" fn(HDC) -> i32;

/// Trampoline to the real `wglSwapBuffers`, set once the hook is committed.
static ORIGINAL_SWAP: OnceLock<WglSwapBuffersFn> = OnceLock::new();

/// Detour: draw a red square into the current frame, then swap as usual.
unsafe extern "system" fn hooked_swap_buffers(hdc: HDC) -> i32 {
    unsafe {
        // The back buffer was just cleared to black by the app's render loop;
        // we add a centered red quad (default GL projection maps -1..1 to the
        // viewport, so [-0.5, 0.5] is a square in the middle).
        glColor3f(1.0, 0.0, 0.0);
        glRectf(-0.5, -0.5, 0.5, 0.5);
        ORIGINAL_SWAP.get().expect("original wglSwapBuffers set")(hdc)
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

extern "system" fn wndproc(hwnd: HWND, msg: u32, w: WPARAM, l: LPARAM) -> LRESULT {
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
        // --- Create a visible window that owns an OpenGL context ---
        let hinstance = GetModuleHandleW(std::ptr::null());
        let class_name = wide("NeoHookGLDemo");
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
            wide("neohook - opengl hook (red square is drawn by the hook)").as_ptr(),
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

        let hdc = GetDC(hwnd);
        let mut pfd: PIXELFORMATDESCRIPTOR = std::mem::zeroed();
        pfd.nSize = std::mem::size_of::<PIXELFORMATDESCRIPTOR>() as u16;
        pfd.nVersion = 1;
        pfd.dwFlags = PFD_DRAW_TO_WINDOW | PFD_SUPPORT_OPENGL | PFD_DOUBLEBUFFER;
        pfd.iPixelType = PFD_TYPE_RGBA;
        pfd.cColorBits = 32;
        pfd.iLayerType = PFD_MAIN_PLANE as u8;
        let format = ChoosePixelFormat(hdc, &pfd);
        if format == 0 || SetPixelFormat(hdc, format, &pfd) == 0 {
            println!("skipped: no usable OpenGL pixel format");
            return Ok(());
        }
        let hglrc = wglCreateContext(hdc);
        if hglrc.is_null() || wglMakeCurrent(hdc, hglrc) == 0 {
            println!("skipped: could not create an OpenGL context");
            return Ok(());
        }
        glViewport(0, 0, WIN_SIZE, WIN_SIZE);

        // --- Install the hook: resolve the export's address by hand, then
        //     inline-hook that exact pointer.
        let opengl32 = GetModuleHandleW(wide("opengl32.dll").as_ptr());
        let swap_ptr = GetProcAddress(opengl32, c"wglSwapBuffers".as_ptr() as *const u8)
            .expect("wglSwapBuffers must exist");
        let swap_buffers: WglSwapBuffersFn = std::mem::transmute(swap_ptr);

        let mut tx = DetourTransaction::begin();
        let tramp = tx.attach(swap_ptr as *mut u8, hooked_swap_buffers as *const u8)?;
        let _hooks = tx.commit()?;
        let _ = ORIGINAL_SWAP.set(std::mem::transmute::<*mut u8, WglSwapBuffersFn>(tramp));
        println!("hooked opengl32!wglSwapBuffers - close the window to exit");

        // --- Render loop: only ever clear to black, then swap. The swap routes
        //     through the detour, which is what actually draws the red square. ---
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
            glClearColor(0.0, 0.0, 0.0, 1.0);
            glClear(GL_COLOR_BUFFER_BIT);
            swap_buffers(hdc);
        }

        // --- Tear down: RAII restores wglSwapBuffers, then free GL + window. ---
        drop(_hooks);
        wglMakeCurrent(std::ptr::null_mut(), std::ptr::null_mut());
        wglDeleteContext(hglrc);
        ReleaseDC(hwnd, hdc);
        DestroyWindow(hwnd);
    }

    Ok(())
}
