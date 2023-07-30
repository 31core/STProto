# STProto
## Introduction
STProto (Secure Transport Protocol) is an End-to-End Encryption network protocol. Like OpenSSL, it's a Session Layer Protocol, it focuses on secure transport bitween server and client, and provides a universal API which is similar to socket.

## Language bindings
|Language|Interface|
|--------|---------|
|Rust    |Native   |

## Get start
With STProto, you can write a simple `server` and `client` like this.

`server.rs`:
```rust
use std::io::*;
use stproto::connection::*;

fn main() -> std::io::Result<()> {
    let mut server = STServer::bind("localhost", 5000)?;
    server.listen()?;
    let client = server.accept();
    let mut data = Vec::new();
    client.read_to_end(&mut data)?;
    println!("{:?}", data);
    Ok(())
}
```

`client.rs`:
```rust
use std::io::*;
use stproto::connection::*;

fn main() -> std::io::Result<()> {
    let mut client = STClient::connect("localhost", 5000)?;
    client.write_all(b"test")?;
    Ok(())
}
```

If it runs properly, you will get:
```shell
$ ./server
[116, 101, 115, 116]
```

## Bugs & Reports
You can report a bug through email `31core@tutanota.com`.
