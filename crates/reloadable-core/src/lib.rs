//! A abstract reloadable state core traits.

/// Something that can perform a single load operation.
pub trait Loader {
    /// The value to load.
    type Value;
    /// The error we can encounter while loading.
    type Error;

    /// Load the value.
    fn load(
        &mut self,
    ) -> impl std::future::Future<Output = Result<Self::Value, Self::Error>> + Send;
}
