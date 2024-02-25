//! The certificate file formats.

use std::str::FromStr;

/// Format of the certificate/key file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// PEM format.
    PEM,
    /// DER format
    /// PKCS8 specifically, other formats are not supported via this DER.
    DER,
}

/// Error for the format parsing.
#[derive(Debug, thiserror::Error)]
#[error("unknown format: {0}")]
pub struct FormatParseError(pub String);

impl FromStr for Format {
    type Err = FormatParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "pem" => Self::PEM,
            "der" => Self::DER,
            other => return Err(FormatParseError(other.to_owned())),
        })
    }
}
