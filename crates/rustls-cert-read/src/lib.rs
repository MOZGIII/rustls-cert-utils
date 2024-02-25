//! The traits for abstract private keys and certs reading.

/// Read a single private key.
pub trait ReadKey {
    /// An error that can occur while reading.
    type Error;

    /// Perform the reading.
    fn read_key(
        &self,
    ) -> impl std::future::Future<
        Output = Result<rustls_pki_types::PrivateKeyDer<'static>, Self::Error>,
    > + Send;
}

/// Read a list of certificates.
///
/// Inteaded for reading a single full certificate chain.
pub trait ReadCerts {
    /// An error that can occur while reading.
    type Error;

    /// Perform the reading.
    fn read_certs(
        &self,
    ) -> impl std::future::Future<
        Output = Result<Vec<rustls_pki_types::CertificateDer<'static>>, Self::Error>,
    > + Send;
}
