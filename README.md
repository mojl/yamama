# Yamama

Yamama is a developer friendly and sans I/O WebRTC implementation in Rust.

## What Yamama has so far?

- Authenticating STUN binding requests and responding to them
- Establishing DTLS
- Establishing SRTP
- Encrypting and decrypting with SRTP
- Parsing RTP
- Resequencing packets

This is enough to write a basic SFU or a transport for an AI agent. Demos will be published soon.

## Working on

- Getting closer to zero-copy
- SCTP
- Unit tests
- Elimating potential panics (guard clauses around lengths)

## Contributing

Yamama is not mature enough to accept issues or pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE.txt) file for details.
