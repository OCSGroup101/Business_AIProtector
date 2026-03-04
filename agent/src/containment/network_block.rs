// Network block containment
// Windows: Windows Filtering Platform (WFP)
// macOS:   pf (pfctl) — Phase 3
// Linux:   iptables / nftables — Phase 3

use anyhow::Result;
use tracing::info;

pub async fn block_network(ip: &str) -> Result<()> {
    if ip.is_empty() {
        anyhow::bail!("Empty IP address for network block");
    }

    info!(ip, "Blocking network connection to IP");

    #[cfg(target_os = "windows")]
    {
        block_windows_wfp(ip)
    }
    #[cfg(target_os = "macos")]
    {
        block_macos_pf(ip).await
    }
    #[cfg(target_os = "linux")]
    {
        block_linux_iptables(ip).await
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        tracing::warn!(ip, "Network block not implemented for this platform");
        Ok(())
    }
}

#[cfg(target_os = "windows")]
fn block_windows_wfp(ip: &str) -> Result<()> {
    // Phase 1: Implement WFP filter rule via FwpmFilterAdd0
    // For now: use netsh as a fallback
    use std::process::Command;
    let output = Command::new("netsh")
        .args([
            "advfirewall",
            "firewall",
            "add",
            "rule",
            "name=OpenClaw_Block",
            "dir=out",
            "action=block",
            &format!("remoteip={}", ip),
        ])
        .output()?;
    if !output.status.success() {
        anyhow::bail!("netsh failed: {}", String::from_utf8_lossy(&output.stderr));
    }
    info!(ip, "Network blocked via Windows Firewall (netsh)");
    Ok(())
}

#[cfg(target_os = "macos")]
async fn block_macos_pf(ip: &str) -> Result<()> {
    // Phase 3: pfctl implementation
    tracing::warn!(ip, "macOS network block (Phase 3)");
    Ok(())
}

#[cfg(target_os = "linux")]
async fn block_linux_iptables(ip: &str) -> Result<()> {
    use tokio::process::Command;
    let status = Command::new("iptables")
        .args(["-A", "OUTPUT", "-d", ip, "-j", "DROP"])
        .status()
        .await?;
    if !status.success() {
        anyhow::bail!("iptables failed for IP: {}", ip);
    }
    info!(ip, "Network blocked via iptables");
    Ok(())
}
