use neohook::TransactionCore;
use std::error::Error;
use std::ptr;
use std::sync::OnceLock;

type Hwnd = *mut core::ffi::c_void;
type Uint = u32;
type Int = i32;

const MB_OK: Uint = 0x0000;

#[link(name = "user32")]
unsafe extern "system" {
    fn MessageBoxA(hwnd: Hwnd, text: *const u8, caption: *const u8, ty: Uint) -> Int;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetModuleHandleA(name: *const u8) -> *mut core::ffi::c_void;
}

type MessageBoxAFn = unsafe extern "system" fn(Hwnd, *const u8, *const u8, Uint) -> Int;

static ORIGINAL_MESSAGEBOXA: OnceLock<MessageBoxAFn> = OnceLock::new();

unsafe extern "system" fn message_box_a_detour(
    hwnd: Hwnd,
    _text: *const u8,
    _caption: *const u8,
    ty: Uint,
) -> Int {
    println!("[iat detour] MessageBoxA intercepted");

    let original = ORIGINAL_MESSAGEBOXA
        .get()
        .copied()
        .expect("ORIGINAL_MESSAGEBOXA not initialized");

    let new_text = b"Hooked by NeoHook via IAT!\0";
    let new_caption = b"NeoHook IAT Example\0";

    unsafe { original(hwnd, new_text.as_ptr(), new_caption.as_ptr(), ty) }
}

fn main() -> Result<(), Box<dyn Error>> {
    unsafe {
        MessageBoxA(
            ptr::null_mut(),
            c"Before hook".as_ptr() as *const u8,
            c"NeoHook".as_ptr() as *const u8,
            MB_OK,
        );
    }

    let module = unsafe { GetModuleHandleA(ptr::null()) };
    if module.is_null() {
        return Err("GetModuleHandleA(NULL) failed".into());
    }

    let mut tx = TransactionCore::begin();
    tx.attach_iat(
        module,
        "USER32.dll",
        "MessageBoxA",
        message_box_a_detour as *const () as *const u8,
    )?;

    let hooks = tx.commit()?;

    let original =
        unsafe { std::mem::transmute::<*const u8, MessageBoxAFn>(hooks[0].original_ptr()) };

    let _ = ORIGINAL_MESSAGEBOXA.set(original);

    unsafe {
        MessageBoxA(
            ptr::null_mut(),
            c"This text should be replaced".as_ptr() as *const u8,
            c"This caption should be replaced".as_ptr() as *const u8,
            MB_OK,
        );
    }

    for hook in hooks {
        hook.unhook()?;
    }

    unsafe {
        MessageBoxA(
            ptr::null_mut(),
            c"After unhook".as_ptr() as *const u8,
            c"NeoHook".as_ptr() as *const u8,
            MB_OK,
        );
    }

    Ok(())
}
