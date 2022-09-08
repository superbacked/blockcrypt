# BlockCrypt (beta)

## Encrypt one or more secrets with plausible deniability by design.

BlockCrypt uses Base58 to render one or more AES-256-CBC-encrypted secrets indistinguishable from each other and padding yielding ciphertext “blocks” of fixed size that one can print as QR codes.

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
    message: "foo",
    passphrase: "decor gooey wish kept pug",
  },
]

const block = await encrypt(secrets, kdf)
// {
//   salt: 'PZE3jTZh45dkU6Du2H4T1j',
//   iv: '35Trmr54uFiqdd7xTs4iM7',
//   ciphertext: '5fwe9NVe1omHDCWy5hPAk1Vne2XvwFCHAWBLjwxnFFFGm4tvhQVY55N9o5RnVGA1gd5EfX8xxWYZGxnbeUM9sqK8SzbCi2R5nA4K2zJ4oc4j6HFBiYkVq4JCfuAgoq2KwY1VSqtfBkcEMHqasDv263pbFdMQUiQDGDTCKZPCfDzqTUsFF19jKX51JPin8AxU7ywZ1vsWjLjmo41zVAX1jCLi1gD5tg1XqbaGVcSodx5pjWrgATSF9gT5JHgXMgng2tWRgsW3itpRe3nfb4ZQNCGGv4JCv3HSvzs2kt3SfsjFCkQR8SRK5eBdLKzGVUYhx4cs3dXTW1ujUegag3p8yuGf5uuzydAiFePz7Kq5hcHMfQpBj6YBaFKwe3y5Z8bk2yZ8LoyaF5xWSTkG8qkKQVXY3556JU3xovwxE75BhZnW3cTpDYX7sQ1nEYCjcVF3gQZqkcEfsb29J7k9yNa99VKidyQkjdwHZbXRWwidNrmVuS9Wu7RyYmsQ6SSXX4EhWAUz1UFSMfftuP7VAsUpEETVAKYAnBXLxNEYjbKsgLvEGkFAgGZiobk3byJQeGcwa1eLtRCAuuy6vww5pPpMz6pfdofF3EfEGzP9FxKnZ8FVtBvRiwfLU6wk8VLUPvhyqhqsRQqJzX2nGotJZ5F1nrsBX8aLW1oSpcb2cEw6eVAzF7WFm37PEypDbbjXw4kdUxvhMZs4RqRcBzbs2D4kxjvUu4fhH3zoqCrT5ZZDC9cFTUFaGe6i2mcfWQmaoav5hvY5RrQ4UCs1GPZorcY5fHDbkh86MZu5ZmiNkkMETGBD2ycn63djVdBhdHAT4g1M2gMUgCoQbTVePdoymHgGchcH9gS3oKjH9a5oyuff6ydKynQ6D4qGrjeFaZnVmBaCEgLNNbzGAuiHTwL692K61udXYLi4uw2T16VpUGDrfUiVgD8h6R9UagLFAC5vaz6QHFTfceM3pnvQCE4Vq7rf9EPs51GLEbyLCtXda45yZuJ4yCGeCPrKMNHLw44ppnkY',
//   needles: [ 'acid', 'cold', 'curry' ]
// }

const secret = await decrypt(
  "grunt daisy chow barge pants",
  "PZE3jTZh45dkU6Du2H4T1j",
  "35Trmr54uFiqdd7xTs4iM7",
  "5fwe9NVe1omHDCWy5hPAk1Vne2XvwFCHAWBLjwxnFFFGm4tvhQVY55N9o5RnVGA1gd5EfX8xxWYZGxnbeUM9sqK8SzbCi2R5nA4K2zJ4oc4j6HFBiYkVq4JCfuAgoq2KwY1VSqtfBkcEMHqasDv263pbFdMQUiQDGDTCKZPCfDzqTUsFF19jKX51JPin8AxU7ywZ1vsWjLjmo41zVAX1jCLi1gD5tg1XqbaGVcSodx5pjWrgATSF9gT5JHgXMgng2tWRgsW3itpRe3nfb4ZQNCGGv4JCv3HSvzs2kt3SfsjFCkQR8SRK5eBdLKzGVUYhx4cs3dXTW1ujUegag3p8yuGf5uuzydAiFePz7Kq5hcHMfQpBj6YBaFKwe3y5Z8bk2yZ8LoyaF5xWSTkG8qkKQVXY3556JU3xovwxE75BhZnW3cTpDYX7sQ1nEYCjcVF3gQZqkcEfsb29J7k9yNa99VKidyQkjdwHZbXRWwidNrmVuS9Wu7RyYmsQ6SSXX4EhWAUz1UFSMfftuP7VAsUpEETVAKYAnBXLxNEYjbKsgLvEGkFAgGZiobk3byJQeGcwa1eLtRCAuuy6vww5pPpMz6pfdofF3EfEGzP9FxKnZ8FVtBvRiwfLU6wk8VLUPvhyqhqsRQqJzX2nGotJZ5F1nrsBX8aLW1oSpcb2cEw6eVAzF7WFm37PEypDbbjXw4kdUxvhMZs4RqRcBzbs2D4kxjvUu4fhH3zoqCrT5ZZDC9cFTUFaGe6i2mcfWQmaoav5hvY5RrQ4UCs1GPZorcY5fHDbkh86MZu5ZmiNkkMETGBD2ycn63djVdBhdHAT4g1M2gMUgCoQbTVePdoymHgGchcH9gS3oKjH9a5oyuff6ydKynQ6D4qGrjeFaZnVmBaCEgLNNbzGAuiHTwL692K61udXYLi4uw2T16VpUGDrfUiVgD8h6R9UagLFAC5vaz6QHFTfceM3pnvQCE4Vq7rf9EPs51GLEbyLCtXda45yZuJ4yCGeCPrKMNHLw44ppnkY",
  kdf,
  "cold" // One can optionally supply needle to significantly speed up decryption
)
// this is a test
// yo
```
