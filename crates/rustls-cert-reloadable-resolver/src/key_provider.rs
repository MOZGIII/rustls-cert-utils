//! The [`rustls::crypto::KeyProvider`] implementation.

/// A wrapper for [`&'static dyn rustls::crypto::KeyProvider`] that implements
/// [`rustls::crypto::KeyProvider`].
#[derive(Debug)]
pub struct Dyn(pub &'static dyn rustls::crypto::KeyProvider);

impl rustls::crypto::KeyProvider for Dyn {
    fn load_private_key(
        &self,
        key_der: rustls::pki_types::PrivateKeyDer<'static>,
    ) -> Result<std::sync::Arc<dyn rustls::sign::SigningKey>, rustls::Error> {
        self.0.load_private_key(key_der)
    }
}

/// A wrapper for anything that can borrow [`rustls::crypto::CryptoProvider`] that implements
/// [`rustls::crypto::KeyProvider`].
pub struct FromCrypto<T>(pub T)
where
    T: std::borrow::Borrow<rustls::crypto::CryptoProvider>;

impl<T> rustls::crypto::KeyProvider for FromCrypto<T>
where
    T: std::borrow::Borrow<rustls::crypto::CryptoProvider> + Send + Sync,
{
    fn load_private_key(
        &self,
        key_der: rustls::pki_types::PrivateKeyDer<'static>,
    ) -> Result<std::sync::Arc<dyn rustls::sign::SigningKey>, rustls::Error> {
        let crypto_provider: &rustls::crypto::CryptoProvider = self.0.borrow();
        crypto_provider.key_provider.load_private_key(key_der)
    }
}

impl<T> std::fmt::Debug for FromCrypto<T>
where
    T: std::borrow::Borrow<rustls::crypto::CryptoProvider>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let crypto_provider: &rustls::crypto::CryptoProvider = self.0.borrow();
        f.debug_tuple("FromCrypto").field(crypto_provider).finish()
    }
}
