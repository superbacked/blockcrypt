# Blockcrypt (beta)

## Encrypt one or more secrets with plausible deniability by design.

Blockcrypt is used to encrypt one or more secrets (up to 5 by default) using encrypted headers which are indistinguisable from each other and padding resulting in plausible deniability by design.

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

// Update example below

const block = await encrypt(secrets, kdf)
// {
//   salt: 'Com4/aFtBjaGdvbjgi5UNw==',
//   iv: 'u05uhhQe3NDtCf39rsxnig==',
//   headers: 'g2a/fztnusowrRuY0HMQo4ctZd74Mnh30P5AR9HWBawUCBbAAnkWAbpt+gx59eIlh1h7sVdFWrRoxpIlmtKBE2jkixnZBlPMEE0pKqA4MoMolEOer/DfWg6LbMhSMqen',
//   data: '+S9sn/cq8SqLz2gh9tcmlVZLG3F0I6UaXobM5czus7k/J5mcgqzvcVVCAFdCdUxgXhtAr/tcVlOENAub8nEHxYgKEpSMBjfg+O21SbtnRT2Kn9E4XJlvrwwk1faEMH5PI0DZwaSi5mMJ5QIWnK56wDQVL8YAeF7WqojJ9v2EWcP00zi7LB02N22EN3B3cR3Azej+s2m9Atz++NSKnuAeNBYor8kbKdwkKUPfbf7UKM6kBpRAueBz4fX0D3mXmu7TVo6LGIDbGoZKa0SFmXPVLmGR23hX8LgFBP0l9kWqSQ8Se1iPuSm9PEwurF9Tkb6AjWQRmOtwuOTyANJ4bXSANcAOtlsIA5LBqjci+FgVxOpk3KIaqO1GfG84Ax9oHzqZGVvK3oydTJDt1SczXIGnUY/D6rOct82ZPgnEz8Fw403Xy5CyaxZO0cLMVxfzj4qGC6x9EkLF20OQ2+cobu4qTda0uOdcJ9bsqVEz4W++AhesNF/klkd+MCBF+9wMxg=='
// }

const secret = await decrypt(
  "grunt daisy chow barge pants",
  "Com4/aFtBjaGdvbjgi5UNw==",
  "u05uhhQe3NDtCf39rsxnig==",
  "g2a/fztnusowrRuY0HMQo4ctZd74Mnh30P5AR9HWBawUCBbAAnkWAbpt+gx59eIlh1h7sVdFWrRoxpIlmtKBE2jkixnZBlPMEE0pKqA4MoMolEOer/DfWg6LbMhSMqen",
  "+S9sn/cq8SqLz2gh9tcmlVZLG3F0I6UaXobM5czus7k/J5mcgqzvcVVCAFdCdUxgXhtAr/tcVlOENAub8nEHxYgKEpSMBjfg+O21SbtnRT2Kn9E4XJlvrwwk1faEMH5PI0DZwaSi5mMJ5QIWnK56wDQVL8YAeF7WqojJ9v2EWcP00zi7LB02N22EN3B3cR3Azej+s2m9Atz++NSKnuAeNBYor8kbKdwkKUPfbf7UKM6kBpRAueBz4fX0D3mXmu7TVo6LGIDbGoZKa0SFmXPVLmGR23hX8LgFBP0l9kWqSQ8Se1iPuSm9PEwurF9Tkb6AjWQRmOtwuOTyANJ4bXSANcAOtlsIA5LBqjci+FgVxOpk3KIaqO1GfG84Ax9oHzqZGVvK3oydTJDt1SczXIGnUY/D6rOct82ZPgnEz8Fw403Xy5CyaxZO0cLMVxfzj4qGC6x9EkLF20OQ2+cobu4qTda0uOdcJ9bsqVEz4W++AhesNF/klkd+MCBF+9wMxg==",
  kdf
)
// this is a test
// yo
```
