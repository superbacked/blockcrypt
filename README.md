# Blockcrypt

## Compact multi-secret encryption

Blockcrypt is a compact encryption scheme for storing one or more secrets in
fixed-size ciphertext blocks, optimized for constrained media like QR codes. It
uses encrypted headers that are indistinguishable from data and noise, with
plausible deniability as a natural side effect of the design.

> Maintained and used in production by [Superbacked](https://superbacked.com/).

## Features

- **Zero dependencies**: implemented using Node.js built-ins only
- **Fixed-size ciphertext blocks**: uniform output size, regardless of number or
  size of secrets
- **Multi-secret support**: encrypt one or more secrets independently
- **Strong cryptography**: ChaCha20-Poly1305 AEAD with HKDF-based key separation
- **Efficient padding**: 8-byte alignment using ISO/IEC 7816-4 style padding
- **Noise filling**: unused space is filled with random data
- **Plausible deniability**: when the first secret is revealed, no evidence of
  additional secrets can be proven
- **Optimized for constrained media**: particularly suited for QR codes or
  similar fixed-capacity channels

## Installation

```console
$ npm install blockcrypt
```

## Usage (simplified for demonstration purposes)

```typescript
import { decrypt, encrypt, Secret } from "blockcrypt"

const secrets: Secret[] = [
  {
    key: Buffer.from([
      4, 72, 156, 132, 66, 216, 156, 26, 55, 162, 221, 77, 214, 13, 146, 94,
      146, 239, 47, 156, 123, 68, 210, 35, 142, 146, 52, 193, 214, 82, 109, 220,
    ]),
    message: Buffer.from(
      "trust vast puppy supreme public course output august glimpse reunion kite rebel virus tail pass enhance divorce whip edit skill dismiss alpha divert ketchup",
    ),
  },
  {
    key: Buffer.from([
      158, 198, 159, 43, 229, 18, 213, 1, 55, 116, 184, 62, 75, 237, 50, 184,
      123, 168, 31, 97, 208, 209, 209, 238, 42, 139, 98, 45, 31, 146, 7, 56,
    ]),
    message: Buffer.from("this is a test\nyo"),
  },
  {
    key: Buffer.from([
      180, 252, 249, 18, 136, 98, 214, 30, 168, 200, 64, 253, 65, 47, 210, 164,
      66, 60, 44, 101, 109, 239, 173, 17, 50, 217, 41, 106, 3, 129, 59, 132,
    ]),
    message: Buffer.from("yo"),
  },
]

const block = await encrypt(secrets, 1024)

console.log(block)
// <Buffer 03 56 d7 03 c3 70 73 6e 4e f9 c6 85 42 3a 73 a3 53 af 0c 7e 5f 13 85 41 b6 34 84 0d 0b 85 8d 98 8f 46 f3 95 e2 76 e7 d1 0d 13 c8 26 88 68 c5 71 02 e1 ... 974 more bytes>

const message = await decrypt(secrets[1].key, block)

console.log(message)
// <Buffer 74 68 69 73 20 69 73 20 61 20 74 65 73 74 0a 79 6f>

console.log(message.toString())
// this is a test
// yo
```
