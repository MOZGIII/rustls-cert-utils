//! A abstract reloadable state.

use std::sync::Arc;

use arc_swap::ArcSwap;
use tokio::sync::Mutex;

pub use reloadable_core as core;

/// A generic reloadable shared state.
pub struct Reloadable<T, R> {
    /// The value.
    value: ArcSwap<T>,
    /// The reloader.
    loader: Mutex<R>,
}

impl<T, L> Reloadable<T, L> {
    /// Create a new [`Reloadable`] with a specified initial value.
    pub fn new(loader: L, initial_value: Arc<T>) -> Self {
        let loader = Mutex::new(loader);
        let value = ArcSwap::new(initial_value);
        Self { loader, value }
    }

    /// Get the currently loaded value.
    pub fn get(&self) -> Arc<T> {
        self.value.load_full()
    }

    /// Store new value and return the old one.
    pub fn set(&self, value: Arc<T>) -> Arc<T> {
        self.value.swap(value)
    }
}

impl<T, L> Reloadable<T, L>
where
    L: reloadable_core::Loader<Value = T>,
{
    /// Load the initial value and create a new [`Reloadable`].
    pub async fn init_load(mut loader: L) -> Result<(Self, Arc<T>), L::Error> {
        let loaded = loader.load().await?;
        let loaded = Arc::new(loaded);
        let reloadable = Self::new(loader, Arc::clone(&loaded));
        Ok((reloadable, loaded))
    }

    /// Reload the value, store it and return the newly loaded value.
    ///
    /// If loader fails with an error, the stored value doesn't change.
    pub async fn reload(&self) -> Result<Arc<T>, L::Error> {
        let mut loader = self.loader.lock().await;
        let reloaded = loader.load().await?;
        let reloaded = Arc::new(reloaded);
        drop(self.set(Arc::clone(&reloaded)));
        Ok(reloaded)
    }
}

impl<T, R> std::fmt::Debug for Reloadable<T, R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Reloadable").finish_non_exhaustive()
    }
}
