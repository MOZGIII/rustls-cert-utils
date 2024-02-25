//! The traits for abstract private keys and certs reading.

/// Read a single private key.
#[async_trait::async_trait]
pub trait ReadKey {
    /// An error that can occur while reading.
    type Error;

    /// Perform the reading.
    async fn read_key(&self) -> Result<rustls_pki_types::PrivateKeyDer<'static>, Self::Error>;
}

/// Read a list of certificates.
///
/// Inteaded for reading a single full certificate chain.
#[async_trait::async_trait]
pub trait ReadCerts {
    /// An error that can occur while reading.
    type Error;

    /// Perform the reading.
    async fn read_certs(
        &self,
    ) -> Result<Vec<rustls_pki_types::CertificateDer<'static>>, Self::Error>;
}
