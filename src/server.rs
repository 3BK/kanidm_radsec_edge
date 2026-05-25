use crate::config::ServerConfig;
use governor::{Quota, RateLimiter};
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration; // Added for maintenance task
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::signal;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

// Note: Removed the invalid `radius_packet` crate imports.
use radius_server::dictionary::Dictionary;

#[allow(dead_code)]
const RADSEC_SHARED_SECRET: &str = "radsec";

pub async fn run(
    cfg: ServerConfig,
    tls_config: rustls::ServerConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(&cfg.bind_address).await?;
    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));

    let quota = Quota::per_second(NonZeroU32::new(cfg.max_connections_per_sec).unwrap());
    let rate_limiter = Arc::new(RateLimiter::keyed(quota));

    // CRITICAL: Memory Maintenance Task
    // Without this, the RateLimiter will grow indefinitely in memory.
    let limiter_clone = rate_limiter.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            limiter_clone.retain_recent();
            debug!("Rate limiter memory swept");
        }
    });

    info!(
        action = "network_bind",
        address = %cfg.bind_address,
        status = "success",
        "Listening for RadSec connections"
    );

    // Load dictionary
    let dictionary = Dictionary::load_from_file("./dictionary")
        .unwrap_or_else(|_| Dictionary::parse_from_str("").unwrap());
    let dictionary = Arc::new(dictionary);

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::mpsc::channel::<()>(1);

    tokio::spawn(async move {
        signal::ctrl_c().await.expect("Failed to listen for ctrl_c");
        info!(
            action = "shutdown_signal",
            "Received termination signal, shutting down gracefully..."
        );
        let _ = shutdown_tx.send(()).await;
    });

    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((stream, peer_addr)) => {
                        let ip = peer_addr.ip();

                        if rate_limiter.check_key(&ip).is_err() {
                            warn!(
                                action = "rate_limit_exceeded",
                                source_ip = %ip,
                                "Connection dropped due to rate limiting"
                            );
                            continue;
                        }

                        let tls_acceptor = tls_acceptor.clone();
                        let dict_clone = Arc::clone(&dictionary);

                        tokio::spawn(async move {
                            match tls_acceptor.accept(stream).await {
                                Ok(tls_stream) => {
                                    info!(
                                        action = "tls_handshake",
                                        source_ip = %ip,
                                        "mTLS session established (P-384/PQ)"
                                    );

                                    match radsec_stream_handler(tls_stream, dict_clone).await {
                                        Ok(_) => info!(action = "radius_session", source_ip = %ip, status = "closed"),
                                        Err(e) => error!(action = "radius_session", source_ip = %ip, error = %e),
                                    }
                                }
                                Err(e) => {
                                    error!(
                                        action = "tls_handshake",
                                        source_ip = %ip,
                                        error = %e,
                                        "TLS handshake failed"
                                    );
                                }
                            }
                        });
                    }
                    Err(e) => error!(action = "network_accept", error = %e),
                }
            }
            _ = shutdown_rx.recv() => {
                info!(action = "server_shutdown", "Server stopped accepting new connections");
                break;
            }
        }
    }

    Ok(())
}

async fn radsec_stream_handler(
    mut stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    dictionary: Arc<Dictionary>,
) -> Result<(), std::io::Error> {
    let mut header_buf = [0u8; 4];

    loop {
        match stream.read_exact(&mut header_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                info!(action = "tls_session_end", "Client disconnected gracefully");
                break;
            }
            Err(e) => return Err(e),
        }

        let length = u16::from_be_bytes([header_buf[2], header_buf[3]]) as usize;

        if !(20..=4096).contains(&length) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "RFC 6614 Violation: Invalid RADIUS packet length: {}",
                    length
                ),
            ));
        }

        let mut payload = vec![0u8; length - 4];
        stream.read_exact(&mut payload).await?;

        let mut full_packet = header_buf.to_vec();
        full_packet.extend_from_slice(&payload);

        debug!(
            action = "packet_received",
            size = length,
            "Successfully framed RadSec packet"
        );

        let response_bytes = process_radius_packet(&full_packet, &dictionary).await?;

        if !response_bytes.is_empty() {
            stream.write_all(&response_bytes).await?;
            stream.flush().await?;
        }
    }

    Ok(())
}

async fn process_radius_packet(
    _request_bytes: &[u8],
    _dictionary: &Dictionary,
) -> Result<Vec<u8>, std::io::Error> {
    // INTEGRATION POINT:
    // Routing logic here
    Ok(vec![])
}
