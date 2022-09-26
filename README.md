# Blockcrypt (beta)

## Encrypt one or more secrets with plausible deniability by design.

Blockcrypt is used to encrypt one or more secrets (up to 4 by default) using encrypted headers which are indistinguishable from each other and padding resulting in plausible deniability by design.

## Installation

```console
$ npm install blockcrypt
```

## Usage (simplified for demonstration purposes)

```typescript
import { encrypt, decrypt, Secret } from "blockcrypt"

const secrets: Secret[] = [
  {
    message:
      "trust vast puppy supreme public course output august glimpse reunion kite rebel virus tail pass enhance divorce whip edit skill dismiss alpha divert ketchup",
    passphrase: "lip gift name net sixth",
  },
  {
    message: "this is a test\nyo",
    passphrase: "grunt daisy chow barge pants",
  },
  {
    message: Buffer.from("yo"),
    passphrase: "decor gooey wish kept pug",
  },
]

const block = await encrypt(secrets, kdf)

console.log(block)
// {
//   salt: <Buffer 0a 89 b8 fd a1 6d 06 36 86 76 f6 e3 82 2e 54 37>,
//   iv: <Buffer bb 4e 6e 86 14 1e dc d0 ed 09 fd fd ae cc 67 8a>,
//   headers: <Buffer 50 93 bc 9b dc 28 7b 40 ab 12 4c 87 a8 eb 8b 37 d0 0d f7 1e f0 91 33 a9 ad 26 1e 14 73 1a 32 6d bd cf a9 7b 0a 67 97 78 ee c8 95 c5 28 ae ac ad 5f 2d ... 14 more bytes>,
//   data: <Buffer 4e 2f bc 42 3e 88 1e 35 d8 cb 88 ff 4f 43 60 6f 02 5f f2 81 f6 f7 b8 32 84 80 e3 a9 c5 fe f0 0b 02 b9 cc c8 be 06 d3 d4 85 96 62 cc 0a 27 0e 5d 61 4a ... 334 more bytes>
// }

const message = await decrypt(
  "grunt daisy chow barge pants",
  block.salt,
  block.iv,
  block.headers,
  block.data,
  kdf
)

console.log(message)
// <Buffer 74 68 69 73 20 69 73 20 61 20 74 65 73 74 0a 79 6f>

console.log(message.toString())
// this is a test
// yo
```
