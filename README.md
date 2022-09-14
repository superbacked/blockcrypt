# Blockcrypt (beta)

## Encrypt one or more secrets with plausible deniability by design.

Blockcrypt is used to encrypt one or more secrets (up to 5 by default) using encrypted headers which are indistinguisable from each other and padding resulting in plausible deniability by design.

## Installation

```console
$ npm install blockcrypt
```

## Usage (simplified for demonstration purposes)

```typescript
import { encrypt, decrypt, Secret } from "./index.js"

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
    message: "yo",
    passphrase: "decor gooey wish kept pug",
  },
]

const block = await encrypt(secrets, kdf)
// {
//   salt: 'Com4/aFtBjaGdvbjgi5UNw==',
//   iv: 'u05uhhQe3NDtCf39rsxnig==',
//   headers: 'ZYtwLEiUAXh+BCO31dT79JrKb5AlZ/94wwYG9b/T1JKH0CAZckJsl+v8x7Xr2t8zVOXLMWFoTncNbWblZj6g5PkswLqTlJY8uytKI8NilmVG23STxto9ZdZnlWbdP3BQ',
//   data: 'FgsCYmyDsw1Sk3RzVFxml+YsB5D9656V8Ngk4hoIb57EXfx7UImXOz0dCpAZ5jOl3tli5pU9PC7tEWItMy3j9n9sb1W+x8R3sQzrMp6stdcSMKyOlBP5pCsFHUec9MQb1xyZwwOBlgw7VMMSpkH+dVKMFj/0RapnjpymHAVecY3m7YyOcFDG8Cl+jcqfeVcmb53cW7/B+oaPG+5810gcpscK7ioio7a+TeJU9BKjYfCA0voXF9gTFA6XfRrC9f1sXhdJKms8AsuY6/UoA5h+lUJkKdaHnhvJCqa4ta8Po1iDJ4MTdwuzIp7guRDp46JyBprjkP0A4o0PUB42ycQVoO8v5v+7Lql0Yr8caZRfDZMn77XVZ0q/fvDsr8UC/C5G5mFmS68G2XyyPYIknCxcD2Xp3ULhlXBbg5rYbyogpbYGxURaHXMQ3QfrsGaA4swAGOxGDPQhGdINwW+4+153glrUNXKRj6o0LxgWF6uknZwSpOrAOUVApr/zoS2qmg=='
// }

const secret = await decrypt(
  "grunt daisy chow barge pants",
  "Com4/aFtBjaGdvbjgi5UNw==",
  "u05uhhQe3NDtCf39rsxnig==",
  "ZYtwLEiUAXh+BCO31dT79JrKb5AlZ/94wwYG9b/T1JKH0CAZckJsl+v8x7Xr2t8zVOXLMWFoTncNbWblZj6g5PkswLqTlJY8uytKI8NilmVG23STxto9ZdZnlWbdP3BQ",
  "FgsCYmyDsw1Sk3RzVFxml+YsB5D9656V8Ngk4hoIb57EXfx7UImXOz0dCpAZ5jOl3tli5pU9PC7tEWItMy3j9n9sb1W+x8R3sQzrMp6stdcSMKyOlBP5pCsFHUec9MQb1xyZwwOBlgw7VMMSpkH+dVKMFj/0RapnjpymHAVecY3m7YyOcFDG8Cl+jcqfeVcmb53cW7/B+oaPG+5810gcpscK7ioio7a+TeJU9BKjYfCA0voXF9gTFA6XfRrC9f1sXhdJKms8AsuY6/UoA5h+lUJkKdaHnhvJCqa4ta8Po1iDJ4MTdwuzIp7guRDp46JyBprjkP0A4o0PUB42ycQVoO8v5v+7Lql0Yr8caZRfDZMn77XVZ0q/fvDsr8UC/C5G5mFmS68G2XyyPYIknCxcD2Xp3ULhlXBbg5rYbyogpbYGxURaHXMQ3QfrsGaA4swAGOxGDPQhGdINwW+4+153glrUNXKRj6o0LxgWF6uknZwSpOrAOUVApr/zoS2qmg==",
  kdf
)
// this is a test
// yo
```
