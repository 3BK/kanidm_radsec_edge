use crate::config::TlsConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use std::fs;
use std::sync::Arc;

pub fn build_tls_config(tls_cfg: &TlsConfig) -> Result<ServerConfig, Box<dyn std::error::Error>> {
    // 1. Load Client CA (mTLS Requirement)
    let mut ca_roots = RootCertStore::empty();
    let ca_file = fs::File::open(&tls_cfg.client_ca_path)?;
    for cert in rustls_pemfile::certs(&mut std::io::BufReader::new(ca_file)) {
        ca_roots.add(cert?)?;
    }
    
    // Require valid client certificates (mTLS)
    let client_auth = WebPkiClientVerifier::builder(Arc::new(ca_roots)).build()?;

    // 2. Initialize AWS-LC-RS crypto provider. 
    // This provides FIPS-compliant cryptography, P-384, and Post-Quantum Key Exchange (e.g. Kyber).
    let provider = rustls::crypto::aws_lc_rs::default_provider();

    let mut config = ServerConfig::builder_with_provider(provider.into())
        .with_safe_default_protocol_versions()? // Enforces TLS 1.2/1.3
        .with_client_cert_verifier(client_auth);

    // 3. Load Server Cert
    let cert_file = fs::File::open(&tls_cfg.server_cert_path)?;
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut std::io::BufReader::new(cert_file))
        .map(|r| r.unwrap())
        .collect();

    // 4. Load Private Key from secure local file
    let key_file = fs::File::open(&tls_cfg.private_key_path)?;
    let mut key_reader = std::io::BufReader::new(key_file);
    let key = rustls_pemfile::private_key(&mut key_reader)?
        .ok_or("No private key found")?;

    config.with_single_cert(certs, key)?;
    
    // RadSec ALPN
    config.alpn_protocols.push(b"radius".to_vec());

    Ok(config)
}
