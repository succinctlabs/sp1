pub fn install_toolchain() -> Result<(), Error> {
    // Add error handling and logging
    let target_triple = get_host_target()?;
    
    info!("Installing toolchain for target: {}", target_triple);
    
    // Add version check for Ubuntu 24.04
    #[cfg(target_os = "linux")]
    if let Ok(release) = std::fs::read_to_string("/etc/os-release") {
        if release.contains("24.04") {
            warn!("Ubuntu 24.04 detected - using compatible toolchain settings");
            // Adjust toolchain settings for Ubuntu 24.04
            return install_toolchain_ubuntu_24(target_triple);
        }
    }
    
    // Original installation logic
    // ... existing code ...
}

#[cfg(target_os = "linux")]
fn install_toolchain_ubuntu_24(target: String) -> Result<(), Error> {
    // Use specific compiler flags for Ubuntu 24.04
    let mut cmd = std::process::Command::new("rustc");
    cmd.args(&[
        "+nightly",
        "-C", "target-feature=+crt-static",
        "--target", &target,
    ]);
    
    // Add additional error handling
    if !cmd.status()?.success() {
        return Err(Error::ToolchainInstallFailed);
    }
    
    Ok(())
} 
