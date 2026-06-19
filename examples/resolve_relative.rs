// Demonstrates resolving relative references found by a signature scan.
//
// On x86_64, a sig-scan match usually lands on an instruction that *references*
// the address you want rather than being it: a `call rel32` into a function, or
// a `lea/mov [rip + disp32]` that loads a global. The bytes you matched do not
// contain the absolute target - you have to add the displacement to the address
// just past the instruction. These helpers do exactly that.
/* Expected output (addresses vary):
    call site  @ 0x7ff6...10  ->  call target  0x7ff6...55
    rip-rel    @ 0x7ff6...20  ->  referenced   0x7ff6...2b
    manual resolve matches decoder: true
*/
use neohook::{resolve_call_target, resolve_relative, resolve_rip_relative};

fn main() {
    // A `call rel32` (E8) whose target is +0x40 from the end of the instruction.
    let call_site: [u8; 5] = [0xE8, 0x40, 0x00, 0x00, 0x00];
    let target = unsafe { resolve_call_target(call_site.as_ptr()) }
        .expect("E8 should decode as a near call");
    println!(
        "call site  @ {:p}  ->  call target  {:p}",
        call_site.as_ptr(),
        target
    );

    // The manual, decode-free path computes the same address when you already
    // know the encoding (E8 = opcode at 0, disp32 at offset 1, total length 5).
    let manual = unsafe { resolve_relative(call_site.as_ptr(), 1, 5) };
    println!("manual resolve matches decoder: {}", manual == target);

    // A RIP-relative load: `lea rax, [rip + 0x06]` == 48 8D 05 06 00 00 00.
    let rip_site: [u8; 7] = [0x48, 0x8D, 0x05, 0x06, 0x00, 0x00, 0x00];
    match unsafe { resolve_rip_relative(rip_site.as_ptr()) } {
        Some(referenced) => println!(
            "rip-rel    @ {:p}  ->  referenced   {:p}",
            rip_site.as_ptr(),
            referenced
        ),
        // x86 has no RIP-relative addressing; the helper returns None there.
        None => println!("rip-rel: no RIP-relative operand (expected on x86)"),
    }
}
