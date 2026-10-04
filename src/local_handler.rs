//! Optional bridge to a local handler process over a Unix socket.
//!
//! Domain-free: server messages whose `type` avocado-conn does not handle
//! itself are written to the socket verbatim, one JSON line each, and every
//! JSON line the handler writes back is published on `event/{device_id}`.
//! Off unless `[local_handler] socket` is configured, so devices that don't
//! run a handler behave exactly as before.

use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::mpsc;
use tracing::{info, warn};

/// Inbound queue depth. Commands are rare; a full queue means the handler
/// is gone or wedged, and dropping is better than unbounded growth (the
/// server re-sends unfinished commands on reconnect).
pub const QUEUE: usize = 256;
/// Messages held while the handler is unreachable (it may start after
/// conn, and the server re-sends pending commands only when the device
/// comes online). Oldest dropped beyond this; handlers dedupe by id.
const HOLD: usize = 64;

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

/// Keep a connection to `socket`, forwarding `inbound` lines to it and its
/// lines to `outbox`. Reconnects with backoff; lines that arrive while the
/// handler is unreachable are held (bounded by `HOLD`) and sent on reconnect.
pub async fn run(
    socket: String,
    mut inbound: mpsc::Receiver<String>,
    outbox: mpsc::UnboundedSender<String>,
) {
    let mut backoff = Duration::from_secs(1);
    let mut held: std::collections::VecDeque<String> = Default::default();
    loop {
        match UnixStream::connect(&socket).await {
            Ok(stream) => {
                info!(%socket, held = held.len(), "local handler connected");
                backoff = Duration::from_secs(1);
                let (rd, mut wr) = stream.into_split();
                let mut lines = BufReader::new(rd).lines();
                let mut flushed = true; // false: the held backlog could not be written
                while let Some(m) = held.pop_front() {
                    if wr.write_all(format!("{m}\n").as_bytes()).await.is_err() {
                        held.push_front(m);
                        flushed = false;
                        break;
                    }
                }
                loop {
                    if !flushed {
                        break;
                    }
                    tokio::select! {
                        line = lines.next_line() => match line {
                            Ok(Some(l)) => {
                                if let Some(ev) = outbound(&l) {
                                    let _ = outbox.send(ev);
                                }
                            }
                            Ok(None) | Err(_) => break,
                        },
                        msg = inbound.recv() => {
                            let Some(m) = msg else { return };
                            if wr.write_all(format!("{m}\n").as_bytes()).await.is_err() {
                                warn!("local handler: write failed, holding message");
                                held.push_back(m);
                                break;
                            }
                        }
                    }
                }
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

    #[tokio::test]
    async fn holds_messages_until_the_handler_appears() {
        let dir = std::env::temp_dir().join(format!("lh-hold-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("h.sock");
        let _ = std::fs::remove_file(&path);
        let (in_tx, in_rx) = mpsc::channel(QUEUE);
        let (out_tx, _out_rx) = mpsc::unbounded_channel();
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
        let (out_tx, mut out_rx) = mpsc::unbounded_channel();
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
