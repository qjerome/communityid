![Crates.io Version](https://img.shields.io/crates/v/communityid?style=for-the-badge)
![docs.rs](https://img.shields.io/docsrs/communityid?style=for-the-badge)
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/qjerome/communityid/rust.yml?style=for-the-badge)
![Crates.io MSRV](https://img.shields.io/crates/msrv/communityid?style=for-the-badge)

<!-- cargo-rdme start -->

This crate provides a practical implementation of the [Community ID 
standard](https://github.com/corelight/community-id-spec) for network
flow hashing.

# Features

* `serde`: when enabled implements `serde::Serialize` and `serde::Deserialize` traits

# Example

```rust
use communityid::{Protocol, Flow};
use std::net::Ipv4Addr;

let f = Flow::new(Protocol::UDP, Ipv4Addr::new(192,168,1,42).into(), 4242, Ipv4Addr::new(8,8,8,8).into(), 53);
let f2 = Flow::new(Protocol::UDP,  Ipv4Addr::new(8,8,8,8).into(), 53, Ipv4Addr::new(192,168,1,42).into(), 4242);

// community-id can be base64 encoded
assert_eq!(f.community_id_v1(0).base64(), "1:vTdrngJjlP5eZ9mw9JtnKyn99KM=");

// community-id can be hex encoded
assert_eq!(f2.community_id_v1(0).hexdigest(), "1:bd376b9e026394fe5e67d9b0f49b672b29fdf4a3");

// we can test equality between two community-ids
assert_eq!(f.community_id_v1(0), f2.community_id_v1(0));
``` 

<!-- cargo-rdme end -->
