use neohook::TransactionCore;
use std::error::Error;
use std::ptr;

type HWND = *mut core::ffi::c_void;
type UINT = u32;
type INT = i32;

const MB_OK: UINT = 0x0000;

#[link(name = "user32")]
unsafe extern "system" {
    fn MessageBoxA(hwnd: HWND, text: *const u8, caption: *const u8, ty: UINT) -> INT;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetModuleHandleA(name: *const u8) -> *mut core::ffi::c_void;
}

type MessageBoxAFn = unsafe extern "system" fn(HWND, *const u8, *const u8, UINT) -> INT;

static mut ORIGINAL_MESSAGEBOXA: Option<MessageBoxAFn> = None;

unsafe extern "system" fn message_box_a_detour(
    hwnd: HWND,
    _text: *const u8,
    _caption: *const u8,
    ty: UINT,
) -> INT {
    println!("[iat detour] MessageBoxA intercepted");

    let original = unsafe { ORIGINAL_MESSAGEBOXA.expect("ORIGINAL_MESSAGEBOXA not initialized") };

    let new_text = b"Hooked by NeoHook via IAT!\0";
    let new_caption = b"NeoHook IAT Example\0";

    unsafe { original(hwnd, new_text.as_ptr(), new_caption.as_ptr(), ty) }
}

fn main() -> Result<(), Box<dyn Error>> {
    unsafe {
        MessageBoxA(
            ptr::null_mut(),
            b"Before hook\0".as_ptr(),
            b"NeoHook\0".as_ptr(),
            MB_OK,
        );
    }

    let module = unsafe { GetModuleHandleA(ptr::null()) };
    if module.is_null() {
        return Err("GetModuleHandleA(NULL) failed".into());
    }

    let mut original: *mut u8 = ptr::null_mut();

    let mut tx = TransactionCore::begin();
    tx.attach_iat(
        module,
        "USER32.dll",
        "MessageBoxA",
        message_box_a_detour as *const () as *const u8,
        &mut original as *mut *mut u8,
    )?;

    let hooks = tx.commit()?;

    unsafe {
        ORIGINAL_MESSAGEBOXA = Some(std::mem::transmute::<*mut u8, MessageBoxAFn>(original));
    }

    unsafe {
        MessageBoxA(
            ptr::null_mut(),
            b"This text should be replaced\0".as_ptr(),
            b"This caption should be replaced\0".as_ptr(),
            MB_OK,
        );
    }

    for hook in hooks {
        hook.unhook()?;
    }

    unsafe {
        MessageBoxA(
            ptr::null_mut(),
            b"After unhook\0".as_ptr(),
            b"NeoHook\0".as_ptr(),
            MB_OK,
        );
    }

    Ok(())
}
