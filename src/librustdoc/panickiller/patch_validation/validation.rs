use std::fs::OpenOptions;
use std::io::Write;

use crate::panickiller::patch_generation::patch::Patch;

pub struct Validator<'a> {
    ranked_patches: Vec<&'a mut Patch>,
}

impl<'a> Validator<'a> {
    pub fn new(ranked_patches: Vec<&'a mut Patch>) -> Self {
        Validator { 
            ranked_patches,
        }
    }

    pub fn validate(&mut self) {
        let log_file_path = std::env::current_dir()
            .expect("Failed to get current directory")
            .parent()
            .expect("Failed to get parent directory")
            .join("src")
            .join("log.txt");
        let mut log_file = OpenOptions::new()
            .create(true)
            .write(true)
            .append(true)
            .open(&log_file_path)
            .expect("Failed to open log file");

        for patch in &mut self.ranked_patches {
            let original = patch.origin.file_path.clone().to_str().unwrap().to_string();
            let original_content = std::fs::read_to_string(original.clone())
                .expect("Failed to read original file content");

            writeln!(log_file, "Patching file: {} from {}", original.clone(), patch.file_path)
                .expect("Failed to write to log file");

            let new_content = std::fs::read_to_string(&patch.file_path)
                .expect("Failed to read patch file");
            std::fs::write(&original.clone(), &new_content)
                .expect("Failed to write to original file");

            println!("Running cargo run");
            writeln!(log_file, "Running cargo run")
                .expect("Failed to write to log file");
            let output = std::process::Command::new("cargo")
                .arg("run")
                .arg("--all-features")
                .current_dir(std::env::current_dir()
                    .expect("Failed to get current directory")
                    .parent()
                    .expect("Failed to get parent directory"))
                .output()
                .expect("Failed to execute cargo run");

            println!("Command: cargo run");
            writeln!(log_file, "Command: cargo run")
                .expect("Failed to write to log file");
            println!("Status: {}", output.status);
            if output.status.success() {
                patch.run_result = 0;
            }

            writeln!(log_file, "Status: {}", output.status)
                .expect("Failed to write to log file");
            writeln!(log_file, "Stdout: {}", String::from_utf8_lossy(&output.stdout))
                .expect("Failed to write to log file");
            writeln!(log_file, "Stderr: {}", String::from_utf8_lossy(&output.stderr))
                .expect("Failed to write to log file");

            println!("Running cargo test");
            writeln!(log_file, "Running cargo test").expect("Failed to write to log file");
            let output = std::process::Command::new("cargo")
                .arg("test")
                .arg("--all-features")
                .current_dir(std::env::current_dir().expect("Failed to get current directory"))
                .output()
                .expect("Failed to execute cargo test");

            println!("Command: cargo test");
            writeln!(log_file, "Command: cargo test").expect("Failed to write to log file");
            println!("Status: {}", output.status);
            if output.status.success() {
                patch.test_result = 0;
            }

            writeln!(log_file, "Status: {}", output.status).expect("Failed to write to log file");
            writeln!(log_file, "Stdout: {}", String::from_utf8_lossy(&output.stdout)).expect("Failed to write to log file");
            writeln!(log_file, "Stderr: {}", String::from_utf8_lossy(&output.stderr)).expect("Failed to write to log file");

            // Restore original content
            std::fs::write(&original.clone(), &original_content)
                .expect("Failed to restore original file content");
        }
    }
}
