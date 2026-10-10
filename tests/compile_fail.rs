#![cfg(windows)]

//! Misuse that must be rejected at compile time.
//!
//! Each `tests/ui/*.rs` file starts with `// expect: E####`. The file is built
//! as a binary against this crate and must fail with that error code. Only the
//! code is checked, not the full message, so new compiler releases that reword
//! diagnostics do not break the test.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[test]
fn compile_fail() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let project = root.join("target").join("compile-fail");
    let src = project.join("src");
    fs::create_dir_all(&src).unwrap();

    let mut cases: Vec<PathBuf> = fs::read_dir(root.join("tests").join("ui"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "rs"))
        .collect();
    cases.sort();
    assert!(!cases.is_empty(), "no compile-fail cases found");

    let mut manifest = format!(
        "[package]\nname = \"neohook-compile-fail\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\
         publish = false\n\n[workspace]\n\n[dependencies]\nneohook = {{ path = {:?} }}\n",
        root.display().to_string()
    );
    for case in &cases {
        let name = case.file_stem().unwrap().to_str().unwrap();
        fs::copy(case, src.join(format!("{name}.rs"))).unwrap();
        manifest.push_str(&format!(
            "\n[[bin]]\nname = \"{name}\"\npath = \"src/{name}.rs\"\n"
        ));
    }
    fs::write(project.join("Cargo.toml"), manifest).unwrap();

    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let mut failures = Vec::new();
    for case in &cases {
        let name = case.file_stem().unwrap().to_str().unwrap();
        let source = fs::read_to_string(case).unwrap();
        let expected = source
            .lines()
            .next()
            .and_then(|l| l.strip_prefix("// expect: "))
            .unwrap_or_else(|| panic!("{name}: first line must be `// expect: E####`"))
            .trim();

        let out = Command::new(&cargo)
            .args(["check", "--quiet", "--color", "never", "--bin", name])
            .current_dir(&project)
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);

        if out.status.success() {
            failures.push(format!("{name}: compiled, expected error[{expected}]"));
        } else if !stderr.contains(&format!("error[{expected}]")) {
            failures.push(format!(
                "{name}: expected error[{expected}], got:\n{stderr}"
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n\n"));
}
