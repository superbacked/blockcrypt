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
//   headers: <Buffer 82 a2 59 64 c4 a2 cb 3c 38 a6 88 5c f8 52 6e 45 81 0e 61 3f 93 69 0a fe 96 f7 21 ee 6c fc 2b 01 72 cc f0 0b ed 08 e3 f0 92 3f dd f4 b3 6a 5f cb ef 7f ... 14 more bytes>,
//   data: <Buffer 5c 68 a6 9e 30 e2 cb 34 ed 70 7c 92 fc 57 af f6 4f 55 a4 7e 28 d5 8a 0f 39 bd fa f4 24 ad ca f9 e1 3e cb 37 89 70 d6 2e 18 1f 8d 34 30 95 42 ac a7 a2 ... 334 more bytes>
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
