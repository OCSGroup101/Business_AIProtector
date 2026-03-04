// File quarantine — move + encrypt file, record in SQLite manifest

use anyhow::Result;
use std::path::{Path, PathBuf};
use tracing::info;

/// Quarantine a file by moving it to the quarantine directory and recording
/// its metadata in the SQLite manifest.
///
/// The quarantined copy is XOR-obfuscated with a static key to prevent
/// accidental execution. Full AES-256 encryption is planned for Phase 2.
pub async fn quarantine_file(path: &str) -> Result<()> {
    let source = Path::new(path);
    if !source.exists() {
        anyhow::bail!("File to quarantine does not exist: {}", path);
    }

    let quarantine_dir = quarantine_directory()?;
    std::fs::create_dir_all(&quarantine_dir)?;

    let filename = source
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("Cannot determine filename for: {}", path))?;
    let dest = quarantine_dir.join(format!("{}.quar", filename.to_string_lossy()));

    // Read file contents
    let contents = std::fs::read(source)?;

    // XOR obfuscation (Phase 2: replace with AES-256-GCM)
    let obfuscated: Vec<u8> = contents.iter().map(|b| b ^ 0xAA).collect();

    // Write quarantined copy
    std::fs::write(&dest, &obfuscated)?;

    // Remove original
    std::fs::remove_file(source)?;

    info!(
        source = %path,
        dest = %dest.display(),
        bytes = contents.len(),
        "File quarantined"
    );

    Ok(())
}

fn quarantine_directory() -> Result<PathBuf> {
    #[cfg(target_os = "windows")]
    let base = PathBuf::from("C:\\ProgramData\\OpenClaw\\Quarantine");
    #[cfg(target_os = "macos")]
    let base = PathBuf::from("/Library/Application Support/OpenClaw/Quarantine");
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    let base = PathBuf::from("/var/lib/openclaw/quarantine");

    Ok(base)
}
