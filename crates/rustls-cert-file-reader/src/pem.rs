//! Parse the PEM file format.

use std::io::ErrorKind;

use rustls_pemfile::{read_one, Item};

/// Parse the certificates from PEM.
pub fn parse_certs(
    rd: &mut dyn std::io::BufRead,
) -> Result<Vec<rustls::Certificate>, std::io::Error> {
    let mut certs = Vec::new();

    loop {
        match read_one(rd)? {
            None => return Ok(certs),
            Some(Item::X509Certificate(cert)) => certs.push(rustls::Certificate(cert)),
            _ => {}
        }
    }
}

/// Parse the signle private key from PEM (PKCS8).
pub fn parse_key(rd: &mut dyn std::io::BufRead) -> Result<rustls::PrivateKey, std::io::Error> {
    let key = loop {
        match read_one(rd)? {
            None => {
                return Err(std::io::Error::new(
                    ErrorKind::NotFound,
                    "no key found in the given data".to_string(),
                ))
            }
            Some(Item::RSAKey(key)) | Some(Item::PKCS8Key(key)) | Some(Item::ECKey(key)) => {
                break key
            }
            _ => {}
        }
    };

    // Assert there are no more keys present in the data.
    loop {
        match read_one(rd)? {
            None => break,
            Some(Item::RSAKey(_)) | Some(Item::PKCS8Key(_)) | Some(Item::ECKey(_)) => {
                return Err(std::io::Error::new(
                    ErrorKind::InvalidInput,
                    "more than one key".to_string(),
                ))
            }
            _ => {}
        }
    }

    Ok(rustls::PrivateKey(key))
}
