//! Parse the PEM file format.

use std::io::ErrorKind;

/// Parse the certificates from PEM.
pub fn parse_certs(
    rd: &mut dyn std::io::BufRead,
) -> Result<Vec<rustls_pki_types::CertificateDer<'static>>, std::io::Error> {
    let mut certs = Vec::new();

    loop {
        let Some(item) = read_one(rd)? else {
            return Ok(certs);
        };
        if let Some(cert) = cert_from_pemfile_item(item) {
            certs.push(cert);
        }
    }
}

/// Parse the single private key from PEM (PKCS8).
pub fn parse_key(
    rd: &mut dyn std::io::BufRead,
) -> Result<rustls_pki_types::PrivateKeyDer<'static>, std::io::Error> {
    let key = loop {
        let Some(item) = read_one(rd)? else {
            return Err(std::io::Error::new(
                ErrorKind::NotFound,
                "no key found in the given data".to_string(),
            ));
        };
        if let Some(key) = private_key_from_pemfile_item(item) {
            break key;
        }
    };

    // Assert there are no more keys present in the data.
    loop {
        let Some(item) = read_one(rd)? else {
            break;
        };

        if private_key_from_pemfile_item(item).is_some() {
            return Err(std::io::Error::new(
                ErrorKind::InvalidInput,
                "more than one key".to_string(),
            ));
        }
    }

    Ok(key)
}

/// A type representing a generic PEM file data item.
type PemObjectTuple = (rustls_pki_types::pem::SectionKind, Vec<u8>);

/// Read one item from a PEM file.
fn read_one(rd: &mut dyn std::io::BufRead) -> Result<Option<PemObjectTuple>, std::io::Error> {
    match rustls_pki_types::pem::from_buf(rd) {
        Ok(item) => Ok(item),
        Err(rustls_pki_types::pem::Error::Io(error)) => Err(error),
        // Should not be possible, but we fallback here if it actually happens.
        Err(error) => Err(std::io::Error::other(error)),
    }
}

/// Obtain the private key from a the pemfile item.
/// If the item is not a private key - returns None.
fn private_key_from_pemfile_item(
    (kind, der): PemObjectTuple,
) -> Option<rustls_pki_types::PrivateKeyDer<'static>> {
    <rustls_pki_types::PrivateKeyDer<'static> as rustls_pki_types::pem::PemObject>::from_pem(
        kind, der,
    )
}

/// Obtain the certificate from a the pemfile item.
/// If the item is not a certificate - returns None.
fn cert_from_pemfile_item(
    (kind, der): PemObjectTuple,
) -> Option<rustls_pki_types::CertificateDer<'static>> {
    <rustls_pki_types::CertificateDer<'static> as rustls_pki_types::pem::PemObject>::from_pem(
        kind, der,
    )
}
