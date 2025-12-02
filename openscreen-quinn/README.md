# openscreen-quinn

Quinn-based implementation of the OpenScreen protocol.

This crate provides the integration between:
- `openscreen-proto`: The no_std Sans-IO protocol core
- `quinn`: Pure Rust QUIC implementation

## Usage

```rust
use openscreen_quinn::QuinnClient;

// TODO: Add usage example
let client = QuinnClient::new();
```

## Features

- Pure Rust QUIC implementation via Quinn
- Async/await support with Tokio
- TLS 1.3 with rustls
