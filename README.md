# rscryptodome

A crypto library for Rust.

Usage:

```
cargo add rscryptodome-bctf
```

```rs
use rscryptodome_bctf::{sha256sum, constant_time_eq};

fn main() {
    let hash = sha256sum(b"abc");
    let expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    assert!(constant_time_eq(&hash, expected.as_bytes()));
}
```
