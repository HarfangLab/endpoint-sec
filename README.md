# Endpoint Security - Rust bindings

[Endpoint Security][es] (abbreviated ES here) is a framework provided by Apple for macOS machines for monitoring system events for potentially malicious activity, see the [official documentation][es] for the exact details.

This repository is composed of two Rust crates:

`endpoint-sec-sys` is the raw events translated from C to Rust, with some additional types that have to exist in the crate because of the orphan rules. While you can use the crate directly, no effort have been made to make it easy nor correct.

`endpoint-sec` contains the higher level wrappers. They're much safer and more ergonomic to use but incur a slight overhead cost in certain methods (not all, not even most of them).

[es]: https://developer.apple.com/documentation/endpointsecurity

## MSRV

Current MSRV is 1.76.0. It can be updated in any minor version, though we'll try to be conservative with it.

## Contributing

All contributions are welcome, provided they respect the [Rust Code of Conduct](https://www.rust-lang.org/policies/code-of-conduct). Opening an issue to signal a bug is a contribution!

## License

Dual licensed under Apache 2 and MIT, see the `LICENSE-APACHE` and `LICENSE-MIT` files.
