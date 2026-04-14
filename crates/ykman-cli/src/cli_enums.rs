/// CLI-specific enum wrappers that derive `clap::ValueEnum` for help text.
///
/// These wrap yubikit types so that clap can display valid values in `--help`
/// output, matching the Python CLI behavior.
use clap::ValueEnum;

// ── PIV ──────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum CliKeyType {
    Rsa1024,
    Rsa2048,
    Rsa3072,
    Rsa4096,
    #[value(alias = "ecc-p256", alias = "p256")]
    Eccp256,
    #[value(alias = "ecc-p384", alias = "p384")]
    Eccp384,
    Ed25519,
    X25519,
}

impl From<CliKeyType> for yubikit::piv::KeyType {
    fn from(v: CliKeyType) -> Self {
        match v {
            CliKeyType::Rsa1024 => Self::Rsa1024,
            CliKeyType::Rsa2048 => Self::Rsa2048,
            CliKeyType::Rsa3072 => Self::Rsa3072,
            CliKeyType::Rsa4096 => Self::Rsa4096,
            CliKeyType::Eccp256 => Self::EccP256,
            CliKeyType::Eccp384 => Self::EccP384,
            CliKeyType::Ed25519 => Self::Ed25519,
            CliKeyType::X25519 => Self::X25519,
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum CliMgmtKeyType {
    #[value(alias = "3des")]
    Tdes,
    Aes128,
    Aes192,
    Aes256,
}

impl From<CliMgmtKeyType> for yubikit::piv::ManagementKeyType {
    fn from(v: CliMgmtKeyType) -> Self {
        match v {
            CliMgmtKeyType::Tdes => Self::Tdes,
            CliMgmtKeyType::Aes128 => Self::Aes128,
            CliMgmtKeyType::Aes192 => Self::Aes192,
            CliMgmtKeyType::Aes256 => Self::Aes256,
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum CliPinPolicy {
    Default,
    Never,
    Once,
    Always,
    #[value(alias = "match_once")]
    MatchOnce,
    #[value(alias = "match_always")]
    MatchAlways,
}

impl From<CliPinPolicy> for yubikit::piv::PinPolicy {
    fn from(v: CliPinPolicy) -> Self {
        match v {
            CliPinPolicy::Default => Self::Default,
            CliPinPolicy::Never => Self::Never,
            CliPinPolicy::Once => Self::Once,
            CliPinPolicy::Always => Self::Always,
            CliPinPolicy::MatchOnce => Self::MatchOnce,
            CliPinPolicy::MatchAlways => Self::MatchAlways,
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum CliTouchPolicy {
    Default,
    Never,
    Always,
    Cached,
}

impl From<CliTouchPolicy> for yubikit::piv::TouchPolicy {
    fn from(v: CliTouchPolicy) -> Self {
        match v {
            CliTouchPolicy::Default => Self::Default,
            CliTouchPolicy::Never => Self::Never,
            CliTouchPolicy::Always => Self::Always,
            CliTouchPolicy::Cached => Self::Cached,
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum CliHashAlgorithm {
    #[value(alias = "sha-256")]
    Sha256,
    #[value(alias = "sha-384")]
    Sha384,
    #[value(alias = "sha-512")]
    Sha512,
}

impl From<CliHashAlgorithm> for yubikit::piv::HashAlgorithm {
    fn from(v: CliHashAlgorithm) -> Self {
        match v {
            CliHashAlgorithm::Sha256 => Self::Sha256,
            CliHashAlgorithm::Sha384 => Self::Sha384,
            CliHashAlgorithm::Sha512 => Self::Sha512,
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum CliFormat {
    Pem,
    Der,
}

// ── OpenPGP ──────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum CliKeyRef {
    #[value(alias = "signature")]
    Sig,
    #[value(alias = "decryption")]
    Dec,
    #[value(alias = "authentication")]
    Aut,
    #[value(alias = "attestation")]
    Att,
}

impl From<CliKeyRef> for yubikit::openpgp::KeyRef {
    fn from(v: CliKeyRef) -> Self {
        match v {
            CliKeyRef::Sig => Self::Sig,
            CliKeyRef::Dec => Self::Dec,
            CliKeyRef::Aut => Self::Aut,
            CliKeyRef::Att => Self::Att,
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum CliUif {
    #[value(alias = "disabled")]
    Off,
    #[value(alias = "enabled")]
    On,
    Fixed,
    Cached,
    #[value(alias = "cached_fixed")]
    CachedFixed,
}

impl From<CliUif> for yubikit::openpgp::Uif {
    fn from(v: CliUif) -> Self {
        match v {
            CliUif::Off => Self::Off,
            CliUif::On => Self::On,
            CliUif::Fixed => Self::Fixed,
            CliUif::Cached => Self::Cached,
            CliUif::CachedFixed => Self::CachedFixed,
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum CliOpenpgpPinPolicy {
    Once,
    Always,
}

impl From<CliOpenpgpPinPolicy> for yubikit::openpgp::PinPolicy {
    fn from(v: CliOpenpgpPinPolicy) -> Self {
        match v {
            CliOpenpgpPinPolicy::Once => Self::Once,
            CliOpenpgpPinPolicy::Always => Self::Always,
        }
    }
}

// ── OATH ─────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum CliOathType {
    Totp,
    Hotp,
}

impl From<CliOathType> for yubikit::oath::OathType {
    fn from(v: CliOathType) -> Self {
        match v {
            CliOathType::Totp => Self::Totp,
            CliOathType::Hotp => Self::Hotp,
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum CliOathAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

impl From<CliOathAlgorithm> for yubikit::oath::HashAlgorithm {
    fn from(v: CliOathAlgorithm) -> Self {
        match v {
            CliOathAlgorithm::Sha1 => Self::Sha1,
            CliOathAlgorithm::Sha256 => Self::Sha256,
            CliOathAlgorithm::Sha512 => Self::Sha512,
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum CliOathDigits {
    #[value(name = "6")]
    Six,
    #[value(name = "7")]
    Seven,
    #[value(name = "8")]
    Eight,
}

impl CliOathDigits {
    pub fn as_u8(self) -> u8 {
        match self {
            Self::Six => 6,
            Self::Seven => 7,
            Self::Eight => 8,
        }
    }
}

// ── OTP ──────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum CliOtpSlot {
    #[value(name = "1")]
    One,
    #[value(name = "2")]
    Two,
}

impl From<CliOtpSlot> for yubikit::yubiotp::Slot {
    fn from(v: CliOtpSlot) -> Self {
        match v {
            CliOtpSlot::One => Self::One,
            CliOtpSlot::Two => Self::Two,
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum CliNdefType {
    Uri,
    Text,
}

impl From<CliNdefType> for yubikit::yubiotp::NdefType {
    fn from(v: CliNdefType) -> Self {
        match v {
            CliNdefType::Uri => Self::Uri,
            CliNdefType::Text => Self::Text,
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum CliKeyboardLayout {
    Us,
    Uk,
    De,
    Fr,
    It,
    Bepo,
    Norman,
    Modhex,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum CliHotpDigits {
    #[value(name = "6")]
    Six,
    #[value(name = "8")]
    Eight,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum CliCalcDigits {
    #[value(name = "6")]
    Six,
    #[value(name = "8")]
    Eight,
}

impl CliCalcDigits {
    pub fn as_u8(self) -> u8 {
        match self {
            Self::Six => 6,
            Self::Eight => 8,
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum CliPacing {
    #[value(name = "0")]
    Zero,
    #[value(name = "20")]
    Twenty,
    #[value(name = "40")]
    Forty,
    #[value(name = "60")]
    Sixty,
}

impl CliPacing {
    pub fn as_u8(self) -> u8 {
        match self {
            Self::Zero => 0,
            Self::Twenty => 20,
            Self::Forty => 40,
            Self::Sixty => 60,
        }
    }
}

// ── Config ────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum CliCapability {
    Otp,
    #[value(alias = "fido_u2f")]
    U2f,
    Fido2,
    Oath,
    Piv,
    Openpgp,
    Hsmauth,
}

impl From<CliCapability> for yubikit::management::Capability {
    fn from(v: CliCapability) -> Self {
        match v {
            CliCapability::Otp => Self::OTP,
            CliCapability::U2f => Self::U2F,
            CliCapability::Fido2 => Self::FIDO2,
            CliCapability::Oath => Self::OATH,
            CliCapability::Piv => Self::PIV,
            CliCapability::Openpgp => Self::OPENPGP,
            CliCapability::Hsmauth => Self::HSMAUTH,
        }
    }
}

// ── Security Domain ──────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum CliSdKeyType {
    Scp03,
    Scp11,
}
