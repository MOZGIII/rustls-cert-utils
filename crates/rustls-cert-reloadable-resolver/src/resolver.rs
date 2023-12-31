//! Reloading-related utilities.

/// Reloadable server certificate resolver.
#[derive(Debug)]
pub struct ReloadableResolver<Loader> {
    /// The inner reloadable value.
    reloadable: rustls_cert_reloadable::Reloadable<rustls::sign::CertifiedKey, Loader>,
}

impl<Loader> ReloadableResolver<Loader>
where
    Loader: rustls_cert_reloadable::Loader<Value = rustls::sign::CertifiedKey>,
{
    /// Perform the initial load and construct the [`ReloadableResolver`].
    pub async fn init(loader: Loader) -> Result<Self, Loader::Error> {
        let (reloadable, _) = rustls_cert_reloadable::Reloadable::init_load(loader).await?;
        Ok(Self { reloadable })
    }

    /// Perform the reload.
    pub async fn reload(&self) -> Result<(), Loader::Error> {
        let _ = self.reloadable.reload().await?;
        Ok(())
    }
}

impl<Loader> rustls::server::ResolvesServerCert for ReloadableResolver<Loader>
where
    Loader: rustls_cert_reloadable::Loader<Value = rustls::sign::CertifiedKey>,
    Loader: Send,
{
    fn resolve(
        &self,
        _client_hello: rustls::server::ClientHello,
    ) -> Option<std::sync::Arc<rustls::sign::CertifiedKey>> {
        Some(self.reloadable.get())
    }
}
