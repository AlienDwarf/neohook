// Demonstrates INT3 software-breakpoint hooking.
//
// An INT3 hook patches a single 0xCC byte at the target entry and routes the
// resulting breakpoint through a vectored exception handler, which rewrites the
// instruction pointer to the detour. Unlike a VEH hook - which is limited to the
// four hardware debug registers - there is no four-hook ceiling, so this example
// installs SIX hooks at once to make the point.
/* Expected output:
    before hooks: 1 2 3 4 5 6
    installed 6 INT3 hooks (VEH would cap at 4)
    after hooks:  9999 9999 9999 9999 9999 9999
    after unhook: 1 2 3 4 5 6
*/
use neohook::Int3Hook;
use std::error::Error;

macro_rules! make_target {
    ($name:ident, $val:expr) => {
        #[inline(never)]
        extern "system" fn $name() -> u32 {
            std::hint::black_box($val)
        }
    };
}

make_target!(f1, 1);
make_target!(f2, 2);
make_target!(f3, 3);
make_target!(f4, 4);
make_target!(f5, 5);
make_target!(f6, 6);

extern "system" fn detour() -> u32 {
    9999
}

// Force an indirect call so the optimizer cannot fold in the known return value
// and actually dispatches to the patched entry byte.
fn call(f: extern "system" fn() -> u32) -> u32 {
    let f = std::hint::black_box(f);
    f()
}

fn main() -> Result<(), Box<dyn Error>> {
    let targets: [extern "system" fn() -> u32; 6] = [f1, f2, f3, f4, f5, f6];

    print!("before hooks:");
    for t in targets {
        print!(" {}", call(t));
    }
    println!();

    let d = detour as *const () as *const u8;
    let mut hooks = Vec::new();
    for t in targets {
        let hook = unsafe { Int3Hook::install(t as *const () as *const u8, d) }?;
        hooks.push(hook);
    }
    println!("installed {} INT3 hooks (VEH would cap at 4)", hooks.len());

    print!("after hooks: ");
    for t in targets {
        print!(" {}", call(t));
    }
    println!();

    for h in hooks.drain(..) {
        h.unhook()?;
    }

    print!("after unhook:");
    for t in targets {
        print!(" {}", call(t));
    }
    println!();

    Ok(())
}
