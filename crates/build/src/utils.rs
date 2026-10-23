use std::path::{Path, PathBuf};

use cargo_metadata::Metadata;
use chrono::Local;

pub(crate) fn current_datetime() -> String {
    let now = Local::now();
    now.format("%Y-%m-%d %H:%M:%S").to_string()
}

/// Re-run the cargo command if the Cargo.toml or Cargo.lock file changes.
pub(crate) fn cargo_rerun_if_changed(metadata: &Metadata, program_dir: &Path) {
    // Tell cargo to rerun the script only if program/{src, bin, build.rs, Cargo.toml} changes
    // Ref: https://doc.rust-lang.org/nightly/cargo/reference/build-scripts.html#rerun-if-changed
    let dirs = vec![
        program_dir.join("src"),
        program_dir.join("bin"),
        program_dir.join("build.rs"),
        program_dir.join("Cargo.toml"),
    ];
    for dir in dirs {
        if dir.exists() {
            println!("cargo::rerun-if-changed={}", dir.canonicalize().unwrap().display());
        }
    }

    // Re-run the build script if the workspace root's Cargo.lock changes. If the program is its own
    // workspace, this will be the program's Cargo.lock.
    println!("cargo:rerun-if-changed={}", metadata.workspace_root.join("Cargo.lock").as_str());

    // Re-run if any local dependency changes.
    for package in &metadata.packages {
        for dependency in &package.dependencies {
            if let Some(path) = &dependency.path {
                for path in
                    paths_excluding(path.as_std_path(), metadata.target_directory.as_std_path())
                {
                    println!("cargo:rerun-if-changed={}", path.display());
                }
            }
        }
    }
}

/// Skips build output, which would otherwise make Cargo's recursive directory scan always see changes.
fn paths_excluding(path: &Path, excluded: &Path) -> Vec<PathBuf> {
    if path == excluded || path.file_name() == Some("target".as_ref()) {
        return vec![];
    }
    if !path.is_dir() {
        return vec![path.to_path_buf()];
    }
    let mut children: Vec<PathBuf> =
        std::fs::read_dir(path).unwrap().map(|entry| entry.unwrap().path()).collect();
    children.sort();
    let paths: Vec<PathBuf> =
        children.iter().flat_map(|child| paths_excluding(child, excluded)).collect();
    if paths == children && !excluded.starts_with(path) {
        vec![path.to_path_buf()]
    } else {
        paths
    }
}

#[cfg(test)]
mod tests {
    use super::paths_excluding;

    #[test]
    fn paths_excluding_skips_only_build_output() {
        let root = std::env::temp_dir().join(format!("sp1-build-paths-{}", std::process::id()));
        let (other, program) = (root.join("other"), root.join("program"));
        for dir in [other.join("target"), other.join("src"), program.join("src"), root.join("src")]
        {
            std::fs::create_dir_all(dir).unwrap();
        }
        let not_yet_built = program.join("target");

        assert_eq!(
            paths_excluding(&root, &not_yet_built),
            vec![other.join("src"), program.join("src"), root.join("src")]
        );
        assert_eq!(paths_excluding(&root.join("src"), &not_yet_built), vec![root.join("src")]);

        std::fs::remove_dir_all(root).unwrap();
    }
}
