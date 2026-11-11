//! Optional bridge to a local handler process over a Unix socket.
//!
//! Domain-free: server messages whose `type` avocado-conn does not handle
//! itself are written to the socket as compact JSON, one line each, and every
//! JSON line the handler writes back is published on `event/{device_id}`.
//! Off unless `[local_handler] socket` is configured, so devices that don't
//! run a handler behave exactly as before.

use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::net::unix::OwnedReadHalf;
use tokio::sync::mpsc;
use tracing::{info, warn};

// Delivery to the handler is at-most-once. conn acks each MQTT message as it
// arrives and the server does not resend, so a message dropped by a full
// queue or a full hold buffer is gone; retries are up to the handler's own
// server.

/// Inbound queue depth. A full queue means the handler is gone or wedged;
/// new messages are then dropped rather than growing without bound.
pub const QUEUE: usize = 256;
/// Handler events waiting for MQTT. When full, the bridge stops reading the
/// socket (backpressure onto the handler) instead of buffering; conn's own
/// events use a separate queue and are unaffected.
pub const EVENTS: usize = 64;
/// Messages held while the handler is unreachable (it may start after conn).
/// Oldest dropped beyond this.
const HOLD: usize = 64;
/// Longest handler line accepted: the MQTT packet ceiling minus room for the
/// topic and fixed header, so every accepted event can actually be published.
/// Longer lines are discarded without being buffered whole.
const MAX_LINE: usize = crate::mqtt::MAX_PACKET - 1024;
/// A write the handler doesn't take within this drops the connection; the
/// message is held and retried after reconnecting.
const WRITE_TIMEOUT: Duration = if cfg!(test) {
    Duration::from_millis(300)
} else {
    Duration::from_secs(10)
};

/// Event types avocado-conn itself publishes. A handler may not emit these,
/// so a local process cannot forge tunnel or shadow state.
fn reserved_event(ty: &str) -> bool {
    ty == "shadow" || ty == "update_result" || ty.starts_with("tunnel_")
}

/// Validate one line from the handler: must be a JSON object with a string
/// `type` that conn doesn't own. Returns the line to publish.
pub fn outbound(line: &str) -> Option<String> {
    let line = line.trim();
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    let ty = v.get("type")?.as_str()?;
    if reserved_event(ty) {
        warn!(ty, "local handler: dropping event with a reserved type");
        return None;
    }
    Some(line.to_string())
}

/// Read handler lines (each at most `MAX_LINE`) into `events` until EOF.
async fn read_events(rd: OwnedReadHalf, events: mpsc::Sender<String>) {
    let mut rd = BufReader::new(rd);
    let mut buf = Vec::new();
    loop {
        buf.clear();
        match (&mut rd)
            .take(MAX_LINE as u64 + 1)
            .read_until(b'\n', &mut buf)
            .await
        {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
        if buf.len() > MAX_LINE {
            warn!(max = MAX_LINE, "local handler: dropping oversized line");
            // Skip the rest of the line in bounded chunks.
            while buf.last() != Some(&b'\n') {
                buf.clear();
                match (&mut rd).take(64 * 1024).read_until(b'\n', &mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(_) => {}
                }
            }
            continue;
        }
        if let Some(ev) = std::str::from_utf8(&buf).ok().and_then(outbound)
            && events.send(ev).await.is_err()
        {
            return;
        }
    }
}

/// Write one message line, bounded by `WRITE_TIMEOUT`.
async fn write_line(wr: &mut tokio::net::unix::OwnedWriteHalf, m: &str) -> bool {
    let line = format!("{m}\n");
    matches!(
        tokio::time::timeout(WRITE_TIMEOUT, wr.write_all(line.as_bytes())).await,
        Ok(Ok(()))
    )
}

/// Keep a connection to `socket`, forwarding `inbound` lines to it and its
/// lines to `events`. Reconnects with backoff; lines that arrive while the
/// handler is unreachable are held (bounded by `HOLD`) and sent on reconnect.
pub async fn run(
    socket: String,
    mut inbound: mpsc::Receiver<String>,
    events: mpsc::Sender<String>,
) {
    let mut backoff = Duration::from_secs(1);
    let mut held: std::collections::VecDeque<String> = Default::default();
    loop {
        match UnixStream::connect(&socket).await {
            Ok(stream) => {
                info!(%socket, held = held.len(), "local handler connected");
                backoff = Duration::from_secs(1);
                let (rd, mut wr) = stream.into_split();
                // Reads run in their own task so a handler that writes before
                // it reads can never deadlock against our writes.
                let mut reader = tokio::spawn(read_events(rd, events.clone()));
                let mut ok = true;
                while let Some(m) = held.pop_front() {
                    if !write_line(&mut wr, &m).await {
                        held.push_front(m);
                        ok = false;
                        break;
                    }
                }
                if ok {
                    loop {
                        tokio::select! {
                            _ = &mut reader => break,
                            msg = inbound.recv() => {
                                let Some(m) = msg else {
                                    reader.abort();
                                    return;
                                };
                                if !write_line(&mut wr, &m).await {
                                    warn!("local handler: write failed or timed out, holding message");
                                    held.push_back(m);
                                    break;
                                }
                            }
                        }
                    }
                }
                reader.abort();
                warn!(%socket, "local handler disconnected");
            }
            Err(e) => warn!(%socket, "local handler unreachable: {e}"),
        }
        // Hold (bounded) while waiting so senders never block on a dead
        // handler and a handler that starts late still gets its commands.
        let wait = tokio::time::sleep(backoff);
        tokio::pin!(wait);
        loop {
            tokio::select! {
                _ = &mut wait => break,
                msg = inbound.recv() => match msg {
                    Some(m) => {
                        if held.len() == HOLD {
                            held.pop_front();
                            warn!("local handler unreachable, oldest held message dropped");
                        }
                        held.push_back(m);
                    }
                    None => return,
                },
            }
        }
        backoff = (backoff * 2).min(Duration::from_secs(30));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handler_events_pass_through_unchanged() {
        let l = r#"{"type":"inventory","inventory":{"vm":{}}}"#;
        assert_eq!(outbound(l).as_deref(), Some(l));
    }

    #[test]
    fn reserved_and_malformed_lines_are_dropped() {
        assert!(outbound(r#"{"type":"shadow","tunnels":true}"#).is_none());
        assert!(outbound(r#"{"type":"tunnel_close","tunnel_id":"x"}"#).is_none());
        assert!(outbound(r#"{"type":"update_result","success":true}"#).is_none());
        assert!(outbound(r#"{"type":0}"#).is_none());
        assert!(outbound("not json").is_none());
        assert!(outbound(r#"["type"]"#).is_none());
    }

    fn sock(tag: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("lh-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("h.sock");
        (dir, path)
    }

    #[tokio::test]
    async fn oversized_lines_are_dropped_and_the_stream_continues() {
        let (dir, path) = sock("big");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let (_in_tx, in_rx) = mpsc::channel(QUEUE);
        let (out_tx, mut out_rx) = mpsc::channel(EVENTS);
        tokio::spawn(run(path.to_string_lossy().into(), in_rx, out_tx));
        let (mut s, _) = listener.accept().await.unwrap();
        let big = format!("{{\"type\":\"x\",\"pad\":\"{}\"}}\n", "a".repeat(MAX_LINE));
        s.write_all(big.as_bytes()).await.unwrap();
        s.write_all(b"{\"type\":\"after\"}\n").await.unwrap();
        assert_eq!(out_rx.recv().await.unwrap(), r#"{"type":"after"}"#);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_full_event_queue_pauses_reading_instead_of_dropping() {
        let (dir, path) = sock("bp");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let (_in_tx, in_rx) = mpsc::channel(QUEUE);
        let (out_tx, mut out_rx) = mpsc::channel(1);
        tokio::spawn(run(path.to_string_lossy().into(), in_rx, out_tx));
        let (mut s, _) = listener.accept().await.unwrap();
        for i in 0..5 {
            s.write_all(format!("{{\"type\":\"e\",\"n\":{i}}}\n").as_bytes())
                .await
                .unwrap();
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        for i in 0..5 {
            assert_eq!(
                out_rx.recv().await.unwrap(),
                format!(r#"{{"type":"e","n":{i}}}"#)
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_handler_that_stops_reading_is_dropped_and_the_message_retried() {
        let (dir, path) = sock("stall");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let (in_tx, in_rx) = mpsc::channel(QUEUE);
        let (out_tx, _out_rx) = mpsc::channel(EVENTS);
        tokio::spawn(run(path.to_string_lossy().into(), in_rx, out_tx));
        // First connection never reads; a 1 MiB message can't fit the socket buffer.
        let (_stalled, _) = listener.accept().await.unwrap();
        let big = format!("{{\"type\":\"c\",\"pad\":\"{}\"}}", "b".repeat(1 << 20));
        in_tx.send(big.clone()).await.unwrap();
        // After WRITE_TIMEOUT conn reconnects and resends it whole.
        let (s, _) = listener.accept().await.unwrap();
        let mut lines = BufReader::new(s).lines();
        assert_eq!(lines.next_line().await.unwrap().unwrap(), big);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn holds_messages_until_the_handler_appears() {
        let dir = std::env::temp_dir().join(format!("lh-hold-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("h.sock");
        let _ = std::fs::remove_file(&path);
        let (in_tx, in_rx) = mpsc::channel(QUEUE);
        let (out_tx, _out_rx) = mpsc::channel(EVENTS);
        tokio::spawn(run(path.to_string_lossy().into(), in_rx, out_tx));
        in_tx
            .send(r#"{"type":"command","id":"early"}"#.into())
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let (s, _) = listener.accept().await.unwrap();
        let mut lines = BufReader::new(s).lines();
        assert_eq!(
            lines.next_line().await.unwrap().unwrap(),
            r#"{"type":"command","id":"early"}"#
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn round_trips_through_the_socket_and_survives_reconnect() {
        let dir = std::env::temp_dir().join(format!("lh-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("h.sock");
        let _ = std::fs::remove_file(&path);
        let listener = tokio::net::UnixListener::bind(&path).unwrap();

        let (in_tx, in_rx) = mpsc::channel(QUEUE);
        let (out_tx, mut out_rx) = mpsc::channel(EVENTS);
        tokio::spawn(run(path.to_string_lossy().into(), in_rx, out_tx));

        for round in 0..2 {
            let (s, _) = listener.accept().await.unwrap();
            let (rd, mut wr) = s.into_split();
            let mut lines = BufReader::new(rd).lines();
            in_tx
                .send(format!(r#"{{"type":"command","id":"{round}"}}"#))
                .await
                .unwrap();
            assert_eq!(
                lines.next_line().await.unwrap().unwrap(),
                format!(r#"{{"type":"command","id":"{round}"}}"#)
            );
            wr.write_all(b"{\"type\":\"command_ack\",\"id\":\"x\"}\n{\"type\":\"shadow\"}\n")
                .await
                .unwrap();
            assert_eq!(
                out_rx.recv().await.unwrap(),
                r#"{"type":"command_ack","id":"x"}"#
            );
            // Dropping the stream forces a reconnect for the next round.
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
