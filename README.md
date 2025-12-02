# Rust Implementation of the OpenScreen Protocol

## Disclaimer

**This is an unofficial, experimental prototype and is NOT a production-ready implementation.** The protocol itself is still under development by the W3C, and this code is not supported by any organization.

---

An early draft prototype Rust `no_std` implementation of the W3C OpenScreen Protocol.

## Overview

This project is an exploration of the W3C OpenScreen protocol, implemented in Rust with a focus on a `no_std` and Sans-IO architecture.

*   **Core Logic**: The core crates are `no_std` and use a Sans-IO design, making them suitable for embedded systems and adaptable to any runtime.
*   **Protocol Compliance**: Aims to follow the W3C OpenScreen Protocol specification for SPAKE2 authentication, QUIC transport, and mDNS discovery.
*   **Cross-Platform**: The binaries have been verified on macOS and Linux. The core crates are designed to be platform-agnostic.

**Current Status**: This is a minimally working prototype and is under active development.

## Project Structure

The protocol is implemented as a series of composable crates:

```
openscreen-application/       # W3C Application Protocol (main entry point)
    ↑
openscreen-network/           # W3C Network Protocol (SPAKE2 auth)
    ↑
openscreen-quinn/             # QUIC adapter (runtime integration)
    ↑
openscreen-discovery-mdns/    # mDNS service discovery
```

## Quick Start

### Build and Run

```bash
# Build the project
cargo build --workspace

# Terminal 1: Start receiver
cargo run --bin app-receiver --  --psk test-psk

# Terminal 2: Start sender (auto-discovers receiver)
cargo run --bin app-sender -- --psk test-psk
```

### Run Tests

```bash
cargo test --workspace
```

## References

- [W3C OpenScreen Network Protocol](https://www.w3.org/TR/openscreen-network/)
- [Chromium OpenScreen Implementation](https://chromium.googlesource.com/openscreen/)
- [W3C OpenScreen Protocol Repository](https://github.com/w3c/openscreenprotocol)

---

## License

Apache-2.0
