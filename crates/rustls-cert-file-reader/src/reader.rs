//! Certificate and key files reader.

use std::{io, marker::PhantomData, path::PathBuf};

use crate::Format;

/// Reads the files.
#[derive(Debug)]
pub struct FileReader<T> {
    /// The file path to read.
    pub path: PathBuf,
    /// The file format to read.
    pub format: Format,
    /// The indicator of what's being read.
    pub reading: PhantomData<T>,
}

impl<T> FileReader<T> {
    /// Create a new [`FileReader`].
    pub fn new(path: impl Into<PathBuf>, format: Format) -> Self {
        let path = path.into();
        let reading = PhantomData;
        Self {
            path,
            format,
            reading,
        }
    }

    /// Read the references file as raw bytes.
    async fn read_file(&self) -> Result<Vec<u8>, io::Error> {
        tokio::fs::read(&self.path).await
    }
}

#[async_trait::async_trait]
impl rustls_cert_read::ReadCerts for FileReader<Vec<rustls::Certificate>> {
    type Error = io::Error;

    async fn read_certs(&self) -> Result<Vec<rustls::Certificate>, Self::Error> {
        let data = self.read_file().await?;
        match self.format {
            Format::DER => Ok(vec![rustls::Certificate(data)]),
            Format::PEM => {
                let mut cursor = std::io::Cursor::new(data);
                crate::pem::parse_certs(&mut cursor)
            }
        }
    }
}

#[async_trait::async_trait]
impl rustls_cert_read::ReadKey for FileReader<rustls::PrivateKey> {
    type Error = io::Error;

    async fn read_key(&self) -> Result<rustls::PrivateKey, Self::Error> {
        let data = self.read_file().await?;
        match self.format {
            Format::DER => Ok(rustls::PrivateKey(data)),
            Format::PEM => {
                let mut cursor = std::io::Cursor::new(data);
                crate::pem::parse_key(&mut cursor)
            }
        }
    }
}
