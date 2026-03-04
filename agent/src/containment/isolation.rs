// Full host network isolation — loopback only
// Windows: WFP block-all filter with permit-loopback exception
// macOS:   pf block-all — Phase 3
// Linux:   iptables — Phase 3

use anyhow::Result;
use tracing::info;

pub async fn isolate_host() -> Result<()> {
    info!("HOST ISOLATION INITIATED — blocking all non-loopback network traffic");

    #[cfg(target_os = "windows")]
    {
        isolate_windows()
    }
    #[cfg(not(target_os = "windows"))]
    {
        tracing::warn!("Host isolation not fully implemented for this platform");
        Ok(())
    }
}

#[cfg(target_os = "windows")]
fn isolate_windows() -> Result<()> {
    use std::process::Command;

    // Block all outbound traffic
    Command::new("netsh")
        .args(["advfirewall", "set", "allprofiles", "firewallpolicy",
               "blockinbound,blockoutbound"])
        .status()?;

    // Re-permit loopback (127.0.0.1)
    Command::new("netsh")
        .args(["advfirewall", "firewall", "add", "rule",
               "name=OpenClaw_IsolationPermitLoopback",
               "dir=out", "action=allow",
               "remoteip=127.0.0.1"])
        .status()?;

    info!("Host isolated: all traffic blocked except loopback");
    Ok(())
}

pub async fn lift_isolation() -> Result<()> {
    info!("Lifting host isolation — restoring normal network policy");

    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        Command::new("netsh")
            .args(["advfirewall", "set", "allprofiles", "firewallpolicy",
                   "blockinbound,allowoutbound"])
            .status()?;
        Command::new("netsh")
            .args(["advfirewall", "firewall", "delete", "rule",
                   "name=OpenClaw_IsolationPermitLoopback"])
            .status()?;
        info!("Host isolation lifted");
    }

    Ok(())
}
