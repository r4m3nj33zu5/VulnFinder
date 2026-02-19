use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use vulnfinder_core::fingerprint::fingerprint_service;

#[tokio::test]
async fn identifies_ssh_banner() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let _ = stream
                .write_all(b"SSH-2.0-OpenSSH_9.3p1 Debian-3\r\n")
                .await;
        }
    });

    let fp = fingerprint_service("127.0.0.1", addr.port(), 500)
        .await
        .expect("fingerprint expected");
    assert_eq!(fp.service, "ssh");
    assert_eq!(fp.product.as_deref(), Some("OpenSSH"));
    assert!(fp.evidence.iter().any(|e| e.contains("SSH-2.0")));
}
