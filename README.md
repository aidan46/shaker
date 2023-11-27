# Shaker

[RLPx transport protocol](https://github.com/ethereum/devp2p/blob/master/rlpx.md) handshake implementation in Rust 🦀

CLI application that connect to an Ethereum node and preforms the RLPx handshake with that node.

## Requirements

Software requirements for building and running shaker:

- [Rust](https://www.rust-lang.org/tools/install)
- [cargo](https://doc.rust-lang.org/cargo/getting-started/installation.html) (comes with Rust install)

## Getting started

Clone the repository `git clone git@github.com:aidan46/shaker.git`.

This application takes an [enode](https://ethereum.org/en/developers/docs/networking-layer/network-addresses/#enode) address as input.

Run the application with an enode address as argument.

```bash
RUST_LOG=debug cargo run enode://22a8232c3abc76a16ae9d6c3b164f98775fe226f0917b0ca871128a74a8e9630b458460865bab457221f1d448dd9791d24c4e5d88786180ac185df813a68d4de@3.209.45.79:30303
```

The logging level can be set with the `RUST_LOG` environment variable, default is info.

## Limitations

When sending to many messages to a node within a certain time the node will reject connection, this is expected behavior.
