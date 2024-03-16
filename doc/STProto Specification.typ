#set page(numbering: "1")

#align(center, text(17pt)[STProto Specification])

#align(center, [31core \
    #link("31core@tutanota.com")
])

#set heading(numbering: "1.")

#outline()

= Introduction
STProto is a secure protocol that operates in the session layer of the OSI model. It is designed to provide security and stability for communication sessions between applications. STProto uses encryption, authentication, and integrity mechanisms to protect the data and the session state from unauthorized access or modification.

= Datapack
== Structure
A standard STProto datapack is defined as follow:

```c
struct data_pack {
    uint8_t method;
    uint64_t time_stamp;
    uint8_t encoding;
    uint8_t sha256[32];
    uint32_t size;
    uint8_t *data,
};
```

*Encodings*

#table(
    columns: (auto, auto),
    [*Value*], [*Algorithm / Format*],
    [0], [plain data],
    [1], [zstd],
    [2], [gzip],
    [3], [lzma2],
)

= Handshaking
Many information will be exchanged in this stage.

== Client hello

The first step of the STProto handshake is the client hello message, the client sends its protocol version, client major and minor version to the server. If the server does not support this version of protocol, it will close the connection immediately.

The structure of client hello datapack is as follow:
```c
struct cient_hello_data_pack {
    uint8_t protocol_version;
    uint8_t major_version;
    uint8_t minor_version;
};
```

== Key exchange

The server sends its RSA-3072 public key to the client, the client then encrypt its random key(we call it _seed_) with the server's public key, and sends back to the server. Thus, the server and the client exchanged their key safely. The seed can be of any size, long size of seed performs more safely than short one.

*Supported algorithms*

#table(
    columns: (auto, auto),
    [*Value*], [*Algorithm*],
    [0x01], [AES-128-CBC],
    [0x02], [AES-256-CBC],
    [0x03], [ChaCha20]
)
