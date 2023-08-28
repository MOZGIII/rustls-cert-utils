//! The [`CertifiedKeyLoader`].

/// Load the [`rustls::sign::CertifiedKey`] from the specified paths using the specified readers.
#[derive(Debug)]
pub struct CertifiedKeyLoader<RK, RC> {
    /// Key reader - reads a key from the file.
    pub key_reader: RK,
    /// Certs reader - reads a list of certs from file.
    pub certs_reader: RC,
}

/// An error that can occur while loading the data.
#[derive(Debug, thiserror::Error)]
pub enum CertifiedKeyLoaderError<R: std::error::Error + 'static> {
    /// Reading failed.
    #[error("read: {0}")]
    Read(R),
    /// Key processing failed.
    #[error("key: {0}")]
    Key(rustls::sign::SignError),
}

#[async_trait::async_trait]
impl<RK, RC, E> rustls_cert_reloadable::Loader for CertifiedKeyLoader<RK, RC>
where
    RK: rustls_cert_read::ReadKey<Error = E> + Send,
    RC: rustls_cert_read::ReadCerts<Error = E> + Send,
    E: std::error::Error + Send + 'static,
{
    type Value = rustls::sign::CertifiedKey;
    type Error = CertifiedKeyLoaderError<E>;

    async fn load(&mut self) -> Result<Self::Value, Self::Error> {
        let (certs, key) = {
            let key_fut = self.key_reader.read_key();
            let certs_fut = self.certs_reader.read_certs();
            tokio::try_join!(certs_fut, key_fut).map_err(CertifiedKeyLoaderError::Read)?
        };

        let key = rustls::sign::any_supported_type(&key).map_err(CertifiedKeyLoaderError::Key)?;

        Ok(rustls::sign::CertifiedKey::new(certs, key))
    }
}
