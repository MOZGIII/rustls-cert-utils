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
