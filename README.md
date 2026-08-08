# Yamama

Yamama is a developer friendly and sans I/O WebRTC implementation in Rust.

## What Yamama has so far?

- Authenticating STUN binding requests and responding to them
- Establishing DTLS
- Establishing SRTP
- Encrypting and decrypting with SRTP
- Parsing RTP
- SCTP and data channels
- Resequencing packets

This is enough to write a basic SFU or a transport for an AI agent, the protocols are functional but only have the minimum needed for a WebRTC server to run. 

## Working on

- Implementing DTLS and dropping OpenSSL
- Getting closer to zero-copy
- Unit tests
- Elimating potential panics (guard clauses around lengths)

## Contributing

Yamama is not mature enough to accept issues or pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE.txt) file for details.
