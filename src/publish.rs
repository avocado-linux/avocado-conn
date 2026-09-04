//! Local publish-ingest socket.
//!
//! Turns `avocado-conn` into a generic device→cloud event bus. Any on-device
//! extension (`avocado-logd`, `avocado-metricsd`, …) connects to a Unix socket
//! and writes newline-delimited JSON objects; each valid object is forwarded to
//! the MQTT outbox for publication on `event/{device_id}`.
//!
//! Wire protocol (mirrors the `avocado-rat` control socket):
//!   client → daemon:  one JSON object per line, e.g. `{"type":"metrics",...}\n`
//!   daemon → client:  `{"ok":true}\n` or `{"ok":false,"error":"..."}\n` per line
//!
//! The connection may stay open and stream many frames (a metrics/log agent
//! holds it for the lifetime of a stream). Best-effort: a bind failure disables
//! the socket but never kills the daemon.

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc::UnboundedSender;
use tracing::{error, info, warn};

/// Validate and canonicalize one inbound line into a payload for `event/{id}`.
///
/// Requires a JSON **object** carrying a non-empty string `type` field — the
/// same envelope convention `avocado-conn` already uses for its own `event`
/// messages (`shadow`, `binary_progress`, `tunnel_close`, …). Returns the
/// compact re-serialized form (strips incidental whitespace / trailing newline).
pub fn normalize_publish_line(line: &str) -> Result<String, String> {
    let value: serde_json::Value =
        serde_json::from_str(line).map_err(|e| format!("invalid JSON: {e}"))?;
    let obj = value
        .as_object()
        .ok_or_else(|| "payload must be a JSON object".to_string())?;
    match obj.get("type").and_then(|t| t.as_str()) {
        Some(t) if !t.is_empty() => {}
        _ => return Err("missing string field \"type\"".to_string()),
    }
    serde_json::to_string(&value).map_err(|e| format!("re-serialize failed: {e}"))
}

/// Bind and serve the publish-ingest socket. Runs until the process exits.
///
/// An empty `socket_path` disables the feature. A bind/permission failure logs a
/// warning and returns (the daemon keeps running without the bus).
pub async fn run(socket_path: String, outbox_tx: UnboundedSender<String>) {
    if socket_path.is_empty() {
        info!("publish-ingest socket disabled (empty path)");
        return;
    }

    // Ensure the parent dir exists (e.g. /run/avocado-conn).
    if let Some(parent) = std::path::Path::new(&socket_path).parent()
        && let Err(e) = std::fs::create_dir_all(parent)
    {
        warn!(
            "publish-ingest: cannot create {}: {e}; disabling",
            parent.display()
        );
        return;
    }

    // Remove a stale socket file from a previous run before binding.
    if std::path::Path::new(&socket_path).exists() {
        let _ = std::fs::remove_file(&socket_path);
    }

    let listener = match UnixListener::bind(&socket_path) {
        Ok(l) => l,
        Err(e) => {
            warn!("publish-ingest: bind {socket_path} failed: {e}; disabling");
            return;
        }
    };

    // 0660: only the daemon's user/group may enqueue cloud messages.
    // TODO: chgrp to the `avocado` group once local agents run as that group
    // (std::os::unix::fs::chown + gid lookup) so non-root extensions can write.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o660));
    }

    info!(socket = %socket_path, "publish-ingest socket listening");

    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let tx = outbox_tx.clone();
                tokio::spawn(async move {
                    handle_conn(stream, tx).await;
                });
            }
            Err(e) => error!("publish-ingest accept error: {e}"),
        }
    }
}

/// Handle one client connection: read lines, forward valid payloads, ack each.
async fn handle_conn(stream: UnixStream, outbox_tx: UnboundedSender<String>) {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    loop {
        match lines.next_line().await {
            Ok(Some(line)) => {
                if line.trim().is_empty() {
                    continue;
                }
                let reply = match normalize_publish_line(&line) {
                    Ok(payload) => {
                        if outbox_tx.send(payload).is_err() {
                            serde_json::json!({"ok": false, "error": "outbox closed"})
                        } else {
                            serde_json::json!({"ok": true})
                        }
                    }
                    Err(e) => serde_json::json!({"ok": false, "error": e}),
                };
                let mut out = reply.to_string();
                out.push('\n');
                if writer.write_all(out.as_bytes()).await.is_err() {
                    break; // client went away
                }
            }
            Ok(None) => break, // client closed the connection
            Err(e) => {
                warn!("publish-ingest read error: {e}");
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixStream;

    #[test]
    fn normalize_accepts_object_with_type() {
        let out = normalize_publish_line(r#"{"type":"metrics","cpu":12}"#).unwrap();
        // Re-serialized and parseable; type preserved.
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["type"], "metrics");
        assert_eq!(v["cpu"], 12);
    }

    #[test]
    fn normalize_strips_trailing_whitespace_and_newline() {
        let out = normalize_publish_line("  {\"type\":\"x\"}  \n").unwrap();
        assert_eq!(out, r#"{"type":"x"}"#);
    }

    #[test]
    fn normalize_rejects_non_object() {
        assert!(normalize_publish_line("[1,2,3]").is_err());
        assert!(normalize_publish_line("\"just a string\"").is_err());
        assert!(normalize_publish_line("42").is_err());
    }

    #[test]
    fn normalize_rejects_missing_or_empty_type() {
        assert!(normalize_publish_line(r#"{"cpu":1}"#).is_err());
        assert!(normalize_publish_line(r#"{"type":""}"#).is_err());
        assert!(normalize_publish_line(r#"{"type":5}"#).is_err());
    }

    #[test]
    fn normalize_rejects_invalid_json() {
        assert!(normalize_publish_line("{not json").is_err());
    }

    /// End-to-end, no broker required: a client writes a line to the socket and
    /// the normalized payload lands on the outbox with an `ok` ack.
    #[tokio::test]
    async fn socket_forwards_valid_line_to_outbox() {
        let socket_path = format!(
            "{}/avocado-conn-pubtest-{}.sock",
            std::env::temp_dir().display(),
            std::process::id()
        );
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();

        let sp = socket_path.clone();
        let server = tokio::spawn(async move { run(sp, tx).await });

        // Wait for the listener to come up.
        let mut stream = None;
        for _ in 0..50 {
            if let Ok(s) = UnixStream::connect(&socket_path).await {
                stream = Some(s);
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let stream = stream.expect("connect to publish socket");
        let (reader, mut writer) = stream.into_split();
        let mut reply_lines = BufReader::new(reader).lines();

        writer
            .write_all(b"{\"type\":\"metrics\",\"cpu\":7}\n")
            .await
            .unwrap();

        let payload = rx.recv().await.expect("outbox received a payload");
        let v: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(v["type"], "metrics");
        assert_eq!(v["cpu"], 7);

        let reply = reply_lines.next_line().await.unwrap().unwrap();
        let rv: serde_json::Value = serde_json::from_str(&reply).unwrap();
        assert_eq!(rv["ok"], true);

        server.abort();
        let _ = std::fs::remove_file(&socket_path);
    }

    #[tokio::test]
    async fn socket_nacks_invalid_line() {
        let socket_path = format!(
            "{}/avocado-conn-pubtest-nack-{}.sock",
            std::env::temp_dir().display(),
            std::process::id()
        );
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();

        let sp = socket_path.clone();
        let server = tokio::spawn(async move { run(sp, tx).await });

        let mut stream = None;
        for _ in 0..50 {
            if let Ok(s) = UnixStream::connect(&socket_path).await {
                stream = Some(s);
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let stream = stream.expect("connect to publish socket");
        let (reader, mut writer) = stream.into_split();
        let mut reply_lines = BufReader::new(reader).lines();

        writer.write_all(b"{\"no\":\"type\"}\n").await.unwrap();

        let reply = reply_lines.next_line().await.unwrap().unwrap();
        let rv: serde_json::Value = serde_json::from_str(&reply).unwrap();
        assert_eq!(rv["ok"], false);
        assert!(rx.try_recv().is_err(), "nothing forwarded on a nack");

        server.abort();
        let _ = std::fs::remove_file(&socket_path);
    }
}
