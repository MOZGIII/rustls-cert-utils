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

impl rustls_cert_read::ReadCerts for FileReader<Vec<rustls_pki_types::CertificateDer<'_>>> {
    type Error = io::Error;

    async fn read_certs(
        &self,
    ) -> Result<Vec<rustls_pki_types::CertificateDer<'static>>, Self::Error> {
        let data = self.read_file().await?;
        match self.format {
            Format::DER => Ok(vec![data.into()]),
            Format::PEM => {
                let mut cursor = std::io::Cursor::new(data);
                crate::pem::parse_certs(&mut cursor)
            }
        }
    }
}

impl rustls_cert_read::ReadKey for FileReader<rustls_pki_types::PrivateKeyDer<'_>> {
    type Error = io::Error;

    async fn read_key(&self) -> Result<rustls_pki_types::PrivateKeyDer<'static>, Self::Error> {
        let data = self.read_file().await?;
        match self.format {
            Format::DER => Ok(rustls_pki_types::PrivateKeyDer::Pkcs8(data.into())),
            Format::PEM => {
                let mut cursor = std::io::Cursor::new(data);
                crate::pem::parse_key(&mut cursor)
            }
        }
    }
}
