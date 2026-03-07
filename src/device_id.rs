use anyhow::{Result, bail};
use tracing::info;

/// Trait for built-in device ID providers.
pub trait DeviceIdProvider {
    /// Human-readable name for logging.
    fn name(&self) -> &str;
    /// Attempt to read the hardware ID. Returns `Ok(None)` if this provider
    /// doesn't apply to the current platform (e.g. file not found).
    fn read_id(&self) -> Result<Option<String>>;
}

// ---------------------------------------------------------------------------
// Built-in providers (each behind a Cargo feature flag)
// ---------------------------------------------------------------------------

/// DMI product UUID — x86/x86_64 systems including QEMU.
/// Reads `/sys/class/dmi/id/product_uuid` (requires root).
#[cfg(feature = "id-dmi")]
pub struct DmiProvider;

#[cfg(feature = "id-dmi")]
impl DeviceIdProvider for DmiProvider {
    fn name(&self) -> &str {
        "dmi"
    }
    fn read_id(&self) -> Result<Option<String>> {
        match std::fs::read_to_string("/sys/class/dmi/id/product_uuid") {
            Ok(id) => {
                let id = id.trim().to_string();
                if id.is_empty() || id.eq_ignore_ascii_case("Not Settable") {
                    Ok(None)
                } else {
                    Ok(Some(id))
                }
            }
            Err(_) => Ok(None),
        }
    }
}

/// Device-tree serial number — ARM boards with device tree (Jetson, iMX, etc.).
/// Reads `/sys/firmware/devicetree/base/serial-number`.
#[cfg(feature = "id-devicetree")]
pub struct DeviceTreeSerialProvider;

#[cfg(feature = "id-devicetree")]
impl DeviceIdProvider for DeviceTreeSerialProvider {
    fn name(&self) -> &str {
        "devicetree-serial"
    }
    fn read_id(&self) -> Result<Option<String>> {
        match std::fs::read("/sys/firmware/devicetree/base/serial-number") {
            Ok(bytes) => {
                // Device tree strings may have a trailing NUL byte.
                let id = String::from_utf8_lossy(&bytes)
                    .trim_end_matches('\0')
                    .trim()
                    .to_string();
                if id.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(id))
                }
            }
            Err(_) => Ok(None),
        }
    }
}

/// Raspberry Pi CPU serial — reads the `Serial` field from `/proc/cpuinfo`.
#[cfg(feature = "id-rpi")]
pub struct RpiSerialProvider;

#[cfg(feature = "id-rpi")]
impl DeviceIdProvider for RpiSerialProvider {
    fn name(&self) -> &str {
        "rpi-serial"
    }
    fn read_id(&self) -> Result<Option<String>> {
        let cpuinfo = match std::fs::read_to_string("/proc/cpuinfo") {
            Ok(s) => s,
            Err(_) => return Ok(None),
        };
        for line in cpuinfo.lines() {
            if let Some(rest) = line.strip_prefix("Serial") {
                if let Some(val) = rest.split(':').nth(1) {
                    let val = val.trim().to_string();
                    if !val.is_empty() && val != "0000000000000000" {
                        return Ok(Some(val));
                    }
                }
            }
        }
        Ok(None)
    }
}

/// NXP i.MX silicon-fused unique ID.
/// Reads `/sys/bus/soc/devices/soc0/soc_uid`.
#[cfg(feature = "id-imx")]
pub struct ImxUidProvider;

#[cfg(feature = "id-imx")]
impl DeviceIdProvider for ImxUidProvider {
    fn name(&self) -> &str {
        "imx-uid"
    }
    fn read_id(&self) -> Result<Option<String>> {
        match std::fs::read_to_string("/sys/bus/soc/devices/soc0/soc_uid") {
            Ok(id) => {
                let id = id.trim().to_string();
                if id.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(id))
                }
            }
            Err(_) => Ok(None),
        }
    }
}

/// First permanent NIC MAC address — universal fallback.
/// Reads `/sys/class/net/*/address`, filters by `addr_assign_type == 0`.
#[cfg(feature = "id-nic-mac")]
pub struct NicMacProvider;

#[cfg(feature = "id-nic-mac")]
impl DeviceIdProvider for NicMacProvider {
    fn name(&self) -> &str {
        "nic-mac"
    }
    fn read_id(&self) -> Result<Option<String>> {
        let net_dir = std::path::Path::new("/sys/class/net");
        let Ok(entries) = std::fs::read_dir(net_dir) else {
            return Ok(None);
        };

        let mut candidates: Vec<(String, String)> = Vec::new();
        for entry in entries.flatten() {
            let iface = entry.file_name().to_string_lossy().to_string();

            // Skip virtual interfaces
            if iface == "lo"
                || iface.starts_with("docker")
                || iface.starts_with("veth")
                || iface.starts_with("br-")
                || iface.starts_with("virbr")
            {
                continue;
            }

            // Check addr_assign_type == 0 (permanently assigned)
            let assign_path = net_dir.join(&iface).join("addr_assign_type");
            if let Ok(val) = std::fs::read_to_string(&assign_path) {
                if val.trim() != "0" {
                    continue;
                }
            } else {
                continue;
            }

            // Read MAC address
            let addr_path = net_dir.join(&iface).join("address");
            if let Ok(mac) = std::fs::read_to_string(&addr_path) {
                let mac = mac.trim().to_lowercase();
                // Skip all-zeros MAC
                if mac != "00:00:00:00:00:00" && mac.len() == 17 {
                    candidates.push((iface, mac));
                }
            }
        }

        // Sort by interface name for deterministic selection
        candidates.sort_by(|a, b| a.0.cmp(&b.0));

        Ok(candidates.into_iter().next().map(|(_, mac)| {
            // Normalize: remove colons → "aabbccddeeff"
            mac.replace(':', "")
        }))
    }
}

// ---------------------------------------------------------------------------
// External providers (always available)
// ---------------------------------------------------------------------------

fn read_from_file(path: &str) -> Result<String> {
    let id = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("reading device ID from {path}: {e}"))?
        .trim()
        .to_string();
    if id.is_empty() {
        bail!("empty device ID from file: {path}");
    }
    Ok(id)
}

fn read_from_uboot_env(var: &str) -> Result<String> {
    let output = std::process::Command::new("fw_printenv")
        .arg("-n")
        .arg(var)
        .output()
        .map_err(|e| anyhow::anyhow!("running fw_printenv -n {var}: {e}"))?;
    if !output.status.success() {
        bail!(
            "fw_printenv -n {var} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let id = String::from_utf8(output.stdout)?.trim().to_string();
    if id.is_empty() {
        bail!("empty device ID from uboot-env:{var}");
    }
    Ok(id)
}

fn read_from_exec(cmd_line: &str) -> Result<String> {
    let mut parts = cmd_line.split_whitespace();
    let program = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("empty exec command"))?;
    let args: Vec<&str> = parts.collect();

    let output = std::process::Command::new(program)
        .args(&args)
        .output()
        .map_err(|e| anyhow::anyhow!("running {cmd_line}: {e}"))?;
    if !output.status.success() {
        bail!(
            "exec:{cmd_line} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let id = String::from_utf8(output.stdout)?.trim().to_string();
    if id.is_empty() {
        bail!("empty device ID from exec:{cmd_line}");
    }
    Ok(id)
}

// ---------------------------------------------------------------------------
// Resolver
// ---------------------------------------------------------------------------

/// Resolve a device ID from the given source string.
///
/// Built-in providers: "dmi", "devicetree-serial", "rpi-serial", "imx-uid", "nic-mac"
/// External providers: "file:<path>", "uboot-env:<var>", "exec:<path> [args...]"
pub fn resolve_device_id(source: &str) -> Result<String> {
    // External providers (prefix-based)
    if let Some(path) = source.strip_prefix("file:") {
        let id = read_from_file(path)?;
        info!(provider = "file", path, id = %id, "resolved device ID");
        return Ok(id);
    }
    if let Some(var) = source.strip_prefix("uboot-env:") {
        let id = read_from_uboot_env(var)?;
        info!(provider = "uboot-env", var, id = %id, "resolved device ID");
        return Ok(id);
    }
    if let Some(cmd) = source.strip_prefix("exec:") {
        let id = read_from_exec(cmd)?;
        info!(provider = "exec", cmd, id = %id, "resolved device ID");
        return Ok(id);
    }

    // Built-in providers (name-based)
    let provider: Box<dyn DeviceIdProvider> = match source {
        #[cfg(feature = "id-dmi")]
        "dmi" => Box::new(DmiProvider),
        #[cfg(feature = "id-devicetree")]
        "devicetree-serial" => Box::new(DeviceTreeSerialProvider),
        #[cfg(feature = "id-rpi")]
        "rpi-serial" => Box::new(RpiSerialProvider),
        #[cfg(feature = "id-imx")]
        "imx-uid" => Box::new(ImxUidProvider),
        #[cfg(feature = "id-nic-mac")]
        "nic-mac" => Box::new(NicMacProvider),
        _ => {
            bail!(
                "Unknown device_id_source: \"{source}\"\n\
                 Available built-in providers: {}\n\
                 External: \"file:<path>\", \"uboot-env:<var>\", \"exec:<path> [args...]\"",
                available_providers().join(", ")
            );
        }
    };

    match provider.read_id()? {
        Some(id) => {
            info!(provider = provider.name(), id = %id, "resolved device ID");
            Ok(id)
        }
        None => bail!(
            "device_id_source \"{}\" did not produce an ID on this platform",
            provider.name()
        ),
    }
}

/// List the names of all compiled-in built-in providers.
#[allow(clippy::vec_init_then_push)] // cfg attributes prevent using vec![]
fn available_providers() -> Vec<&'static str> {
    let mut providers = Vec::new();
    #[cfg(feature = "id-dmi")]
    providers.push("dmi");
    #[cfg(feature = "id-devicetree")]
    providers.push("devicetree-serial");
    #[cfg(feature = "id-rpi")]
    providers.push("rpi-serial");
    #[cfg(feature = "id-imx")]
    providers.push("imx-uid");
    #[cfg(feature = "id-nic-mac")]
    providers.push("nic-mac");
    providers
}
