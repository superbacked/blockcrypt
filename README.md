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

const block = await encrypt(secrets, kdf, 1024)

console.log(block)
// <Buffer 0e 2f ee 5f f1 69 df 6a b7 ff 43 ca 65 70 36 6b 38 cf b0 d7 23 cb f2 ca 63 1c 16 bf da 02 da 1c 2f 89 ca fe 29 36 d2 5c 1a 44 c3 32 23 02 56 ba 29 21 ... 974 more bytes>

const message = await decrypt(
  "grunt daisy chow barge pants",
  block
  kdf,
)

console.log(message)
// <Buffer 74 68 69 73 20 69 73 20 61 20 74 65 73 74 0a 79 6f>

console.log(message.toString())
// this is a test
// yo
```