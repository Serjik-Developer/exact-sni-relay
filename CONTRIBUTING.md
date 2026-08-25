# Contributing

Bug reports and focused pull requests are welcome.

Before submitting a change, run:

```bash
cargo fmt --all -- --check
cargo test --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
cargo build --release --locked
```

Changes to ClientHello parsing, relay shutdown, admission, socket marks, or
reload behavior should include regression tests. Do not include production
addresses, credentials, packet captures containing customer data, or private
configuration.
