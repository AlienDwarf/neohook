// Module / PE introspection example.
//
// Lists the modules loaded in this process, then shows the entry point and a
// few exports/imports of a chosen module (kernel32.dll by default).
//
// Run with:  cargo run --example introspect

use neohook::{
    enumerate_exports, enumerate_imports, enumerate_modules, get_entry_point, get_module_handle,
};

fn main() {
    println!("== Loaded modules ==");
    let modules = enumerate_modules();
    for m in modules.iter().take(15) {
        println!("  {:<28} base={:p} size={} bytes", m.name, m.base, m.size);
    }
    if modules.len() > 15 {
        println!("  ... and {} more", modules.len() - 15);
    }

    let target = "kernel32.dll";
    let Some(h) = get_module_handle(target) else {
        eprintln!("\n{target} is not loaded; nothing more to show.");
        return;
    };

    println!("\n== {target} ==");
    match get_entry_point(h) {
        Some(entry) => println!("  entry point: {entry:p}"),
        None => println!("  entry point: <none>"),
    }

    match unsafe { enumerate_exports(h) } {
        Ok(exports) => {
            println!("  exports: {} total, first 10:", exports.len());
            for e in exports.iter().take(10) {
                let name = e.name.as_deref().unwrap_or("<by ordinal>");
                match &e.forwarder {
                    Some(fwd) => println!("    #{:<6} {:<32} -> {}", e.ordinal, name, fwd),
                    None => println!("    #{:<6} {:<32} {:p}", e.ordinal, name, e.address),
                }
            }
        }
        Err(err) => println!("  exports: <error: {err:?}>"),
    }

    match unsafe { enumerate_imports(h) } {
        Ok(imports) => {
            println!("  imports: {} total, first 10:", imports.len());
            for i in imports.iter().take(10) {
                match (&i.name, i.ordinal) {
                    (Some(name), _) => println!("    {} :: {} -> {:p}", i.dll, name, i.address),
                    (None, Some(ord)) => {
                        println!("    {} :: #{} -> {:p}", i.dll, ord, i.address)
                    }
                    (None, None) => println!("    {} :: <unknown> -> {:p}", i.dll, i.address),
                }
            }
        }
        Err(err) => println!("  imports: <error: {err:?}>"),
    }
}
