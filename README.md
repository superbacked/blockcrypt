# Blockcrypt (beta)

## Encrypt one or more secrets with plausible deniability by design.

Blockcrypt is used to encrypt one or more secrets using encrypted headers which
are indistinguishable from each other, data and padding resulting in plausible
deniability by design.

## Installation

```console
$ npm install blockcrypt
```

## Usage (simplified for demonstration purposes)

```typescript
import { decrypt, encrypt, Secret } from "blockcrypt"

const secrets: Secret[] = [
  {
    message:
      "trust vast puppy supreme public course output august glimpse reunion kite rebel virus tail pass enhance divorce whip edit skill dismiss alpha divert ketchup",
    key: Buffer.from([
      4, 72, 156, 132, 66, 216, 156, 26, 55, 162, 221, 77, 214, 13, 146, 94,
      146, 239, 47, 156, 123, 68, 210, 35, 142, 146, 52, 193, 214, 82, 109, 220,
    ]),
  },
  {
    message: "this is a test\nyo",
    key: Buffer.from([
      158, 198, 159, 43, 229, 18, 213, 1, 55, 116, 184, 62, 75, 237, 50, 184,
      123, 168, 31, 97, 208, 209, 209, 238, 42, 139, 98, 45, 31, 146, 7, 56,
    ]),
  },
  {
    message: Buffer.from("yo"),
    key: Buffer.from([
      180, 252, 249, 18, 136, 98, 214, 30, 168, 200, 64, 253, 65, 47, 210, 164,
      66, 60, 44, 101, 109, 239, 173, 17, 50, 217, 41, 106, 3, 129, 59, 132,
    ]),
  },
]

const block = await encrypt(secrets, 1024)

console.log(block)
// <Buffer 52 4f d0 4f 97 33 36 24 6e 62 07 1e 0a 4c 24 cd 42 78 4c 4b 99 6c 03 73 23 de ea 45 2f d6 7f f4 ef bb ce a0 86 e5 94 29 99 53 cf ad 22 6e eb 30 32 54 ... 974 more bytes>

const message = await decrypt(secrets[1].key, block)

console.log(message)
// <Buffer 74 68 69 73 20 69 73 20 61 20 74 65 73 74 0a 79 6f>

console.log(message.toString())
// this is a test
// yo
```
