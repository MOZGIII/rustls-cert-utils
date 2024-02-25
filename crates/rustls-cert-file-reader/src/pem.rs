//! Parse the PEM file format.

use std::io::ErrorKind;

use rustls_pemfile::{read_one, Item};

/// Parse the certificates from PEM.
pub fn parse_certs(
    rd: &mut dyn std::io::BufRead,
) -> Result<Vec<rustls_pki_types::CertificateDer<'static>>, std::io::Error> {
    let mut certs = Vec::new();

    loop {
        let Some(item) = read_one(rd)? else {
            return Ok(certs);
        };
        if let Item::X509Certificate(cert) = item {
            certs.push(cert);
        }
    }
}

/// Parse the signle private key from PEM (PKCS8).
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

/// Obtain the private key from a the pemfile item.
/// If the item is not a private key - returns None.
fn private_key_from_pemfile_item(
    item: rustls_pemfile::Item,
) -> Option<rustls_pki_types::PrivateKeyDer<'static>> {
    Some(match item {
        Item::Pkcs1Key(key) => key.into(),
        Item::Pkcs8Key(key) => key.into(),
        Item::Sec1Key(key) => key.into(),
        _ => return None,
    })
}
