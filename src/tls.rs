//! TLS trust shared by every outbound connection (claim API and MQTT).

use rustls::pki_types::CertificateDer;
use rustls::{ClientConfig, RootCertStore};
use tracing::{info, warn};

/// Client config trusting the bundled Mozilla roots plus the system store,
/// so an image can add a private CA (e.g. via ca-certificates, or
/// `SSL_CERT_FILE`/`SSL_CERT_DIR`) without a rebuild. A missing or broken
/// system store only logs: the bundled roots still work as before.
pub fn client_config() -> ClientConfig {
    let native = rustls_native_certs::load_native_certs();
    for e in &native.errors {
        warn!("system CA store: {e}");
    }
    let roots = root_store(native.certs);
    info!(roots = roots.len(), "TLS trust loaded");
    ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth()
}

/// Bundled roots plus `system`; unparsable system certs are skipped.
fn root_store(system: Vec<CertificateDer<'static>>) -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let (added, ignored) = roots.add_parsable_certificates(system);
    if ignored > 0 {
        warn!(
            added,
            ignored, "system CA store: some certificates were unparsable"
        );
    }
    roots
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::pem::PemObject;

    const PRIVATE_CA: &str = "-----BEGIN CERTIFICATE-----
MIIBlDCCATugAwIBAgIULlb751bDM7U8U6FFxeb5+4pkoRMwCgYIKoZIzj0EAwIw
HzEdMBsGA1UEAwwUYXZvY2Fkby1jb25uIHRlc3QgQ0EwIBcNMjYxMTAyMDMwNzI4
WhgPMjEyNjEwMDkwMzA3MjhaMB8xHTAbBgNVBAMMFGF2b2NhZG8tY29ubiB0ZXN0
IENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEDYcMKKdT+5n4hdzlkWE26LJl
/H/RvFAptVHXboAsgS52dipU8sUa/9f/FhAMx4ZIsZBazl0/lJFumT5PKJ0yPKNT
MFEwHQYDVR0OBBYEFPiVsEx/ky8ySzBfM6WA3ak2a8oLMB8GA1UdIwQYMBaAFPiV
sEx/ky8ySzBfM6WA3ak2a8oLMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwID
RwAwRAIgco6GXChdTjayUoUIsaHxlf6OTRST/31UULCvNNY0XSQCIHvnuR4iYlK6
cHqEtTGACAkDe3RlFtmkOXHSL9vSrcTj
-----END CERTIFICATE-----";

    #[test]
    fn system_cas_are_trusted_alongside_bundled_roots() {
        let bundled = webpki_roots::TLS_SERVER_ROOTS.len();
        let ca = CertificateDer::from_pem_slice(PRIVATE_CA.as_bytes()).unwrap();
        let junk = CertificateDer::from(vec![0u8; 16]);
        let roots = root_store(vec![ca, junk]);
        // The private CA is added, the junk cert skipped, nothing bundled lost.
        assert_eq!(roots.len(), bundled + 1);
        assert_eq!(root_store(vec![]).len(), bundled);
    }
}
