# Lamport-Haskell
A naive implementation of the [Lamport one-time signature scheme](https://en.wikipedia.org/wiki/Lamport_signature) written in Haskell for educational purposes.

This package is intended for **educational purposes only** and is not suitable for production / commercial use.

## Getting Started
- Get and install [stack](https://docs.haskellstack.org/en/stable/install_and_upgrade/);
- `git clone https://github.com/difelicemichael/lamport-haskell.git`;
- `cd lamport-haskell`;
- Run `stack build` inside of the root directory.

## Signature Creation / Message Validation
- Run `stack ghci`, then -
```
λ> -- generate a key pair
λ> key <- Lamport.generateKey
λ>
λ> -- sign a message
λ> let signature = Lamport.sign (_private key) "Hello world!"
λ>
λ> -- verify signature
λ> Lamport.verify (_public key) "Hello world!" signature
True
λ>
λ> -- tampered message will fail signature validation
λ> Lamport.verify (_public key) "He110 w0r1d!" signature
False
λ>
```

## Multi-use Key Reveal
This package also includes a module `KeyReveal`, which demonstrates how reusing Lamport key pairs for signing multiple messages can result in the key pair becoming compromised (*this module serves no other purpose than to demonstrate how an attack of this nature could hypothetically be accomplished*).
