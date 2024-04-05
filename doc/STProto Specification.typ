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

#table(
    columns: (auto, auto, auto, auto, auto, auto, auto, auto, auto),
    [Method], [Session ID], [Timestamp], [Encoding], [SHA-256], [Crypto size], [Crypto area], [Payload size], [Payload],
    [1 byte], [8 bytes], [8 bytes], [1 byte], [32 bytes], [2 bytes], [Variable], [2 bytes], [Variable]
)

*Encodings*

#table(
    columns: (auto, auto),
    [*Value*], [*Algorithm / Format*],
    [0], [plain data],
    [1], [zstd],
    [2], [gzip],
    [3], [lzma2],
)

*Methods*
#table(
    columns: (auto, auto),
    [*Value*], [*Method*],
    [2], [METHOD_SEND],
    [3], [METHOD_OK],
    [4], [METHOD_REQUEST_RESEND]
)

= Handshaking
Many information will be exchanged in this stage.

== Client hello

The first step of the STProto handshake is the client hello message, the client sends its protocol version, client major and minor version to the server. If the server does not support this version of protocol, it will close the connection immediately.

The structure of client hello datapack is as follow:

#table(
    columns: (auto, auto, auto, auto),
    [Protocol version], [Major version], [Minor version], [Session ID],
    [1 byte], [1 byte], [1 byte], [8 bytes],
)

== Key exchange

When the server received the client hello message, it generate an RSA-3072 key pair, and send it to the client. Then the client select a cipher, generate a private key, and send it back to the server via the following structure.

#table(
    columns: (auto, auto, auto),
    [Session ID], [Encryption Type], [RSA Encrypted Key],
    [8 bytes], [1 byte], [Variable]
)

*Supported algorithms*

#table(
    columns: (auto, auto),
    [*Value*], [*Algorithm*],
    [1], [AES-128-GCM],
    [2], [AES-256-GCM],
    [3], [ChaCha20Poly1305],
    [4], [AES-256-CCM],
    [5], [AES-256-CCM]
)
