//! Reloading-related utilities.

/// Reloadable server certificate resolver.
#[derive(Debug)]
pub struct ReloadableResolver<Loader> {
    /// The inner reloadable value.
    reloadable: reloadable_state::Reloadable<rustls::sign::CertifiedKey, Loader>,
}

impl<Loader> ReloadableResolver<Loader>
where
    Loader: reloadable_state::core::Loader<Value = rustls::sign::CertifiedKey>,
{
    /// Perform the initial load and construct the [`ReloadableResolver`].
    pub async fn init(loader: Loader) -> Result<Self, Loader::Error> {
        let (reloadable, _) = reloadable_state::Reloadable::init_load(loader).await?;
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
    Loader: reloadable_state::core::Loader<Value = rustls::sign::CertifiedKey>,
    Loader: Send,
    Loader: std::fmt::Debug,
{
    fn resolve(
        &self,
        _client_hello: rustls::server::ClientHello,
    ) -> Option<std::sync::Arc<rustls::sign::CertifiedKey>> {
        Some(self.reloadable.get())
    }
}

impl<Loader> std::ops::Deref for ReloadableResolver<Loader> {
    type Target = reloadable_state::Reloadable<rustls::sign::CertifiedKey, Loader>;

    fn deref(&self) -> &Self::Target {
        &self.reloadable
    }
}

impl<Loader> std::ops::DerefMut for ReloadableResolver<Loader> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.reloadable
    }
}
