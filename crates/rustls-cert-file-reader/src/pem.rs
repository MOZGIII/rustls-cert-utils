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

/// Parse the signle private key from PEM (PKCS8).
pub fn parse_key(rd: &mut dyn io::BufRead) -> Result<PrivateKeyDer<'static>, io::Error> {
    PrivateKeyDer::from_pem_reader(rd).map_err(into_io_err)
}

fn into_io_err(err: pem::Error) -> io::Error {
    match err {
        pem::Error::Io(error) => error,
        err @ _ => io::Error::other(err),
    }
}
