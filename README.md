# Blockcrypt (beta)

## Encrypt one or more secrets with plausible deniability by design.

Blockcrypt is used to encrypt one or more secrets (up to 4 by default) using encrypted headers which are indistinguisable from each other and padding resulting in plausible deniability by design.

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
//   headers: <Buffer 83 66 bf 7f 3b 67 ba ca 30 ad 1b 98 d0 73 10 a3 87 2d 65 de f8 32 78 77 d0 fe 40 47 d1 d6 05 ac 14 08 16 c0 02 79 16 01 ba 6d fa 0c 79 f5 e2 25 b7 2f ... 14 more bytes>,
//   data: <Buffer c5 93 19 d5 af 16 06 06 cf 68 28 35 d2 cc 02 a5 6f 28 06 b4 2b fc ef 0c c6 8a 8c de 51 9d 8d d8 c6 60 18 4f 9a 26 25 0f 9a fa b3 1e 3d b5 53 01 32 7d ... 334 more bytes>
// }

const secret = await decrypt(
  "grunt daisy chow barge pants",
  block.salt,
  block.iv,
  block.headers,
  block.data,
  kdf
)

console.log(secret)
// <Buffer 74 68 69 73 20 69 73 20 61 20 74 65 73 74 0a 79 6f>

console.log(secret.toString())
// this is a test
// yo
```
