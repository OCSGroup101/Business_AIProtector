// Process termination containment action

use anyhow::Result;
use tracing::{info, warn};

pub async fn terminate_process(pid: u32) -> Result<()> {
    if pid == 0 {
        anyhow::bail!("Cannot terminate process with PID 0");
    }

    info!(pid, "Terminating process");

    #[cfg(target_os = "windows")]
    {
        terminate_windows(pid)
    }
    #[cfg(not(target_os = "windows"))]
    {
        terminate_unix(pid)
    }
}

#[cfg(target_os = "windows")]
fn terminate_windows(pid: u32) -> Result<()> {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};

    unsafe {
        let handle = OpenProcess(PROCESS_TERMINATE, false, pid)?;
        let result = TerminateProcess(handle, 1);
        CloseHandle(handle)?;
        result?;
    }
    info!(pid, "Process terminated via Windows API");
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn terminate_unix(pid: u32) -> Result<()> {
    use std::process::Command;

    let output = Command::new("kill")
        .arg("-9")
        .arg(pid.to_string())
        .output()?;
    if output.status.success() {
        info!(pid, "Process terminated via kill -9");
        Ok(())
    } else {
        anyhow::bail!(
            "kill -9 {} failed: {}",
            pid,
            String::from_utf8_lossy(&output.stderr)
        )
    }
}
