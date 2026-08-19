// SPDX-FileCopyrightText: 2026 Roman Valls Guimera <brainstorm@nopcode.org>
// SPDX-FileCopyrightText: 2026 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2026 Anthony Tambasco <anthony.tambasco@fastmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use embedded_storage::ReadStorage;
use embedded_storage::nor_flash::NorFlash;

use ssh_key::sha2::Digest;

use log::{debug, error};

use sunset::error::Error as SunsetError;

use crate::config::{SSHStampConfig, UartPins};

use sunset::sshwire::{self, OwnOrBorrow};
use sunset_sshwire_derive::{SSHDecode, SSHEncode};

// TODO: [Nice to have] Read the right partition and write there instead of hardcoding offset and size.
pub const CONFIG_VERSION_SIZE: usize = 4;
pub const CONFIG_HASH_SIZE: usize = 32;
pub const CONFIG_AREA_SIZE: usize = 4096;
pub const CONFIG_OFFSET: usize = 0x9000;

// SSHConfig::CURRENT_VERSION must be bumped if any of this struct
#[derive(SSHEncode, SSHDecode)]
struct FlashConfig<'a> {
    version: u8,
    config: OwnOrBorrow<'a, SSHStampConfig>,
    /// sha256 hash of config
    hash: [u8; 32],
}

impl FlashConfig<'_> {
    const BUF_SIZE: usize = 460; // Must be enough to hold the whole config
}

fn config_hash(config: &SSHStampConfig) -> Result<[u8; 32], SunsetError> {
    let mut h = ssh_key::sha2::Sha256::new();
    sshwire::hash_ser(&mut h, config)?;
    Ok(h.finalize().into())
}

/// Loads a `SSHStampConfig` from flash, or creates a new one if none exists.
///
/// `default_mac` is used only when a new config has to be minted (e.g. first
/// boot); the platform reads this from hardware and passes it in.
///
/// `default_uart_pins` is the target-specific UART pin assignment, used when
/// creating a new config. On subsequent boots the pins are loaded from flash.
///
/// # Errors
/// Returns an error if config creation or flash write fails.
pub fn load_or_create<F>(
    flash: &mut F,
    buf: &mut [u8],
    default_mac: [u8; 6],
    default_uart_pins: UartPins,
) -> Result<SSHStampConfig, SunsetError>
where
    F: NorFlash + ReadStorage,
{
    match load_checked(flash, buf) {
        LoadOutcome::Ok(mut c) => {
            debug!("Good existing config");
            if c.wifi_ap_ssid.as_str() == "ssh-stamp" {
                debug!("Migrating insecure default Access Point SSID, regenerating randomly");
                c.wifi_ap_ssid = SSHStampConfig::generate_wifi_ssid()?;
                if c.wifi_ap_pw.is_empty() {
                    c.wifi_ap_pw = SSHStampConfig::generate_wifi_password()?;
                }
                save(flash, buf, &c)?;
            }
            Ok(c)
        }
        // A config exists but failed the version or integrity check (or the
        // flash read errored). Recreating here would silently wipe stored
        // pubkeys, regenerate the host key, and reopen the unauthenticated
        // first-login window, so refuse rather than fail open.
        LoadOutcome::Invalid(e) => {
            error!("Existing config present but invalid; refusing to overwrite it: {e}");
            Err(e)
        }
        // No decodable config at all (blank/erased flash on first boot). This
        // is the only case where minting a fresh config is the right thing.
        LoadOutcome::Absent => {
            debug!("No existing config found, creating a new one");
            create(flash, buf, default_mac, default_uart_pins)
        }
    }
}

/// Creates a new `SSHStampConfig` and saves it to flash.
///
/// # Errors
/// Returns an error if config creation or flash write fails.
pub fn create<F>(
    flash: &mut F,
    buf: &mut [u8],
    default_mac: [u8; 6],
    default_uart_pins: UartPins,
) -> Result<SSHStampConfig, SunsetError>
where
    F: NorFlash,
{
    let c = SSHStampConfig::new(default_mac, default_uart_pins)?;
    save(flash, buf, &c)?;
    // Don't Debug-print the config: it contains the host private key.
    debug!("Created new config");

    Ok(c)
}

/// Result of attempting to load an existing config from flash.
enum LoadOutcome {
    /// A config was decoded and passed the version and integrity checks.
    Ok(SSHStampConfig),
    /// No decodable config was present (blank/erased flash, e.g. first boot).
    /// This is the only outcome for which minting a fresh config is correct.
    Absent,
    /// A config was structurally present but failed the version or hash check,
    /// or the flash read itself errored. The caller must not overwrite it.
    Invalid(SunsetError),
}

/// Reads and validates the config from flash, distinguishing "no config yet"
/// from "a config is present but invalid" so callers can avoid silently
/// wiping stored keys on the latter.
fn load_checked<F>(flash: &mut F, buf: &mut [u8]) -> LoadOutcome
where
    F: ReadStorage,
{
    // If at some point you target a 64bit arch these can truncate and cause
    // corruption of the bootloader or the ota partition.
    let offset = match u32::try_from(CONFIG_OFFSET) {
        Ok(o) => o,
        Err(_) => return LoadOutcome::Invalid(SunsetError::msg("CONFIG_OFFSET overflow")),
    };

    if flash.read(offset, buf).is_err() {
        error!("flash read error 0x{CONFIG_OFFSET:x}");
        // A transient read error is not proof the config is gone; do not wipe.
        return LoadOutcome::Invalid(SunsetError::msg("flash error"));
    }

    // Undecodable bytes mean no config has been written yet (or the region is
    // erased). This is the only path allowed to fall through to create().
    let (flash_config, _used): (FlashConfig, usize) = match sshwire::read_ssh(buf, None) {
        Ok(v) => v,
        Err(_) => return LoadOutcome::Absent,
    };

    if flash_config.version != SSHStampConfig::CURRENT_VERSION {
        error!("wrong config version on decode: {}", flash_config.version);
        return LoadOutcome::Invalid(SunsetError::msg("wrong config version"));
    }

    // OwnOrBorrow::Own is the only variant that can be decoded from bytes
    let config = match flash_config.config {
        OwnOrBorrow::Own(c) => c,
        OwnOrBorrow::Borrow(_) => {
            return LoadOutcome::Invalid(SunsetError::msg("unexpected borrowed config"));
        }
    };

    let calc_hash = match config_hash(&config) {
        Ok(h) => h,
        Err(e) => return LoadOutcome::Invalid(e),
    };

    if calc_hash != flash_config.hash {
        return LoadOutcome::Invalid(SunsetError::msg("bad config hash"));
    }

    LoadOutcome::Ok(config)
}

/// Loads `SSHStampConfig` from flash.
///
/// # Errors
/// Returns an error if flash read fails, config is absent, invalid, or the
/// hash mismatches.
pub fn load<F>(flash: &mut F, buf: &mut [u8]) -> Result<SSHStampConfig, SunsetError>
where
    F: ReadStorage,
{
    match load_checked(flash, buf) {
        LoadOutcome::Ok(c) => Ok(c),
        LoadOutcome::Absent => Err(SunsetError::msg("failed to decode flash config")),
        LoadOutcome::Invalid(e) => Err(e),
    }
}

/// Saves `SSHStampConfig` to flash.
///
/// # Errors
/// Returns an error if flash write fails or config serialization fails.
pub fn save<F>(flash: &mut F, buf: &mut [u8], config: &SSHStampConfig) -> Result<(), SunsetError>
where
    F: NorFlash,
{
    let sc = FlashConfig {
        version: SSHStampConfig::CURRENT_VERSION,
        config: OwnOrBorrow::Borrow(config),
        hash: config_hash(config)?,
    };

    // NB: do not hex_dump `buf` here — the serialized config begins with the
    // Ed25519 host private key and contains the WiFi passwords.
    let l = sshwire::write_ssh(buf, &sc)?;

    debug!("Erasing flash");

    const { assert!(CONFIG_AREA_SIZE > FlashConfig::BUF_SIZE) };

    // Write only the encoded config, rounded up to the flash write
    // granularity, instead of the entire caller buffer. Writing the whole
    // buffer persisted stale trailing RAM to flash and, for a buffer larger
    // than the config area, would write past the erased region into the
    // adjacent partition (NVS/PHY on ESP32).
    let write_len = l
        .checked_next_multiple_of(F::WRITE_SIZE)
        .filter(|n| *n <= buf.len() && *n <= CONFIG_AREA_SIZE)
        .ok_or_else(|| SunsetError::msg("encoded config too large for flash area"))?;

    let offset =
        u32::try_from(CONFIG_OFFSET).map_err(|_| SunsetError::msg("CONFIG_OFFSET overflow"))?;
    let area_size = u32::try_from(CONFIG_AREA_SIZE)
        .map_err(|_| SunsetError::msg("CONFIG_AREA_SIZE overflow"))?;

    flash.erase(offset, offset + area_size).map_err(|_e| {
        error!("flash erase error");
        SunsetError::msg("flash erase error")
    })?;

    flash.write(offset, &buf[..write_len]).map_err(|_e| {
        error!("flash write error");
        SunsetError::msg("flash write error")
    })?;

    debug!("flash save done");
    Ok(())
}
