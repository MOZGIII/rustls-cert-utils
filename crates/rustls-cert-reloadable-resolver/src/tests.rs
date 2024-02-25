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
#[test]
fn traits_satisfied() {
    let crypto_provider = rustls::crypto::ring::default_provider();

    let loader = CertifiedKeyLoader {
        key_provider: key_provider::Dyn(crypto_provider.key_provider),
        key_reader: DummyKeyReader,
        certs_reader: DummyCertsReader,
    };

    let _resolver = ReloadableResolver::init(loader);
}
