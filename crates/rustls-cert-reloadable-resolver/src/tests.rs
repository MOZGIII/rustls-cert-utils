use super::*;

struct DummyKeyReader;

impl rustls_cert_read::ReadKey for DummyKeyReader {
    type Error = std::convert::Infallible;

    async fn read_key(&self) -> Result<rustls::pki_types::PrivateKeyDer<'static>, Self::Error> {
        todo!()
    }
}

struct DummyCertsReader;

impl rustls_cert_read::ReadCerts for DummyCertsReader {
    type Error = std::convert::Infallible;

    async fn read_certs(
        &self,
    ) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, Self::Error> {
        todo!()
    }
}

fn fake_spawn(_f: impl core::future::Future<Output = ()> + 'static + Send) {}

#[test]
fn traits_satisfied() {
    let crypto_provider = rustls::crypto::ring::default_provider();

    let loader = CertifiedKeyLoader {
        key_provider: key_provider::Dyn(crypto_provider.key_provider),
        key_reader: DummyKeyReader,
        certs_reader: DummyCertsReader,
    };

    fake_spawn(async move {
        let resolver = ReloadableResolver::init(loader).await.unwrap();
        resolver.reload().await.unwrap()
    });
}

#[test]
fn with_file_reader() {
    let crypto_provider = rustls::crypto::ring::default_provider();

    let key_reader =
        rustls_cert_file_reader::FileReader::new("key", rustls_cert_file_reader::Format::DER);
    let certs_reader =
        rustls_cert_file_reader::FileReader::new("certs", rustls_cert_file_reader::Format::DER);

    let loader = CertifiedKeyLoader {
        key_provider: key_provider::Dyn(crypto_provider.key_provider),
        key_reader,
        certs_reader,
    };

    fake_spawn(async move {
        let resolver = ReloadableResolver::init(loader).await.unwrap();
        resolver.reload().await.unwrap()
    });
}
