//! Parse the PEM file format.

use std::io;

use rustls_pki_types::{
    pem::{self, PemObject},
    CertificateDer, PrivateKeyDer,
};

/// Parse the certificates from PEM.
pub fn parse_certs(rd: &mut dyn io::BufRead) -> Result<Vec<CertificateDer<'static>>, io::Error> {
    CertificateDer::pem_reader_iter(rd)
        .collect::<Result<Vec<_>, _>>()
        .map_err(into_io_err)
}

/// Parse the single private key from PEM (PKCS8).
pub fn parse_key(rd: &mut dyn io::BufRead) -> Result<PrivateKeyDer<'static>, io::Error> {
    let mut iter = PrivateKeyDer::pem_reader_iter(rd);
    let first_key = match iter.next() {
        Some(key) => key.map_err(into_io_err),
        None => Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no key found in the given data".to_string(),
        )),
    };

    // Assert there are no more keys present in the data
    if iter.next().is_some() {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "more than one key".to_string(),
        ))
    } else {
        first_key
    }
}

fn into_io_err(err: pem::Error) -> io::Error {
    match err {
        pem::Error::Io(error) => error,
        err @ _ => io::Error::other(err),
    }
}
