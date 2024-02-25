//! The [`CertifiedKeyLoader`].

use futures_util::TryFutureExt as _;

/// Load the [`rustls::sign::CertifiedKey`] from the specified paths using the specified readers.
#[derive(Debug)]
pub struct CertifiedKeyLoader<KeyProvider, KeyReader, CertsReader> {
    /// The provider to load the key into.
    pub key_provider: KeyProvider,
    /// Reads a key from the file.
    pub key_reader: KeyReader,
    /// Reads a list of certs from file.
    pub certs_reader: CertsReader,
}

/// An error that can occur while loading the data.
#[derive(Debug, thiserror::Error)]
pub enum CertifiedKeyLoaderError<ReadKey, ReadCerts> {
    /// Reading the key failed.
    #[error("reading key: {0}")]
    ReadKey(ReadKey),
    /// Reading the certificate failed.
    #[error("reading certs: {0}")]
    ReadCerts(ReadCerts),
    /// Key processing failed.
    #[error("loading key: {0}")]
    LoadKey(rustls::Error),
}

#[async_trait::async_trait]
impl<KeyProvider, KeyReader, CertsReader> rustls_cert_reloadable::Loader
    for CertifiedKeyLoader<KeyProvider, KeyReader, CertsReader>
where
    KeyProvider: rustls::crypto::KeyProvider,
    KeyReader: rustls_cert_read::ReadKey + Send,
    CertsReader: rustls_cert_read::ReadCerts + Send,
    KeyReader::Error: std::error::Error + Send + 'static,
    CertsReader::Error: std::error::Error + Send + 'static,
{
    type Value = rustls::sign::CertifiedKey;
    type Error = CertifiedKeyLoaderError<KeyReader::Error, CertsReader::Error>;

    async fn load(&mut self) -> Result<Self::Value, Self::Error> {
        let (certs, key) = {
            let key_fut = self
                .key_reader
                .read_key()
                .map_err(CertifiedKeyLoaderError::ReadKey);
            let certs_fut = self
                .certs_reader
                .read_certs()
                .map_err(CertifiedKeyLoaderError::ReadCerts);
            futures_util::future::try_join(certs_fut, key_fut).await?
        };

        let key = self
            .key_provider
            .load_private_key(key)
            .map_err(CertifiedKeyLoaderError::LoadKey)?;

        Ok(rustls::sign::CertifiedKey::new(certs, key))
    }
}
