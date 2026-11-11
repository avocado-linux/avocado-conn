# Changelog

All notable changes to avocado-conn and the `avocado-ext-connect` extension.
The extension version tracks the program version in `Cargo.toml`.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.0] - 2026-11-10

### Added

- Optional local handler bridge over a Unix socket (`[local_handler] socket`).
  Server messages with a `type` conn doesn't handle are written to the socket
  as one JSON line each, and every line the handler writes is published on
  `event/{device_id}`. Off unless configured (#23).

### Changed

- MQTT accepts and sends packets up to 1 MiB (#23).
- Runtime updates run one at a time. Nudges that arrive mid-update are
  coalesced into one more pass instead of starting a second update (#16).

### Fixed

- The claimed state is written durably with mode 0600, and never into a stale
  temp file (#23).
- `tunnel_close` carries `tunnel_id`, so the server closes torn-down
  tunnels (#21).

### Removed

- The unused WebSocket module (#22).

### Security

- Bump `webpki-roots` and `rustls-webpki` for the eMudhra distrust, and clear
  `cargo audit` (#20).

## [0.1.1] - 2026-09-03

### Changed

- Publish the extension to the 2026/next and 2024/next channels (#17).

## [0.1.0] - 2026-06-24

### Added

- Device claim flow with automatic credential provisioning (#1).
- Active runtime queried via varlink on startup and after an update (#2).
- MQTT over TLS (#5).
- `reclaim_pending` is treated as transient and honours retry-after (#11).
- Packaged and published as the `avocado-ext-connect` extension (#14).

### Fixed

- `tunnel_configure` carries `tunnel_id` (#3).
- The `rat` socket is re-probed so tunnel capability heals itself (#4).
- A 4xx on device claim is terminal, and `Retry-After` is honoured (#7).
- A single rustls 0.23 crypto provider (#12).

[Unreleased]: https://github.com/avocado-linux/avocado-conn/compare/0.2.0...HEAD
[0.2.0]: https://github.com/avocado-linux/avocado-conn/compare/0.1.1...0.2.0
[0.1.1]: https://github.com/avocado-linux/avocado-conn/compare/0.1.0...0.1.1
[0.1.0]: https://github.com/avocado-linux/avocado-conn/releases/tag/0.1.0
