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
//   ciphertext: '5fwe9NVe1omHDCWy5hPAk1Vne2XvwFCHAWBLjwxnFFFGm4tvhQVY55N9o5RnVGA1gd5EfX8xxWYZGxnbeUM9sqK8SzbCi2R5nA4K2zJ4oc4j6HFBiYkVq4JCfuAgoq2KwY1VSqtfBkcEMHqasDv263pbFdMQUiQDGDTCKZPCfDzqTUsFF19jKX51JPin8AxU7ywZ1vsWjLjmo41zVAX1jCLi1gDJ2bxupKeiKsrDvWgXXrkFpbC18CauJuFbbnuoMK3NP7m3itpRe3nfb4ZQNCGGv4JCv2cqpGdmhrXaVfKsP1zvjoNWbSJJPbhzGFJCgyvKsx4Aib3tpByXKkXJEQid27SNshPap2oD27LgnDraNDHgR9tD2euKj9nXFKcFQ22T6DwAqsFS34KVNzCHF6jF8oq9SHHCL2hhCnncgAweKyT8XEwnZBH8XzdJH36HqmpQrTu1V4xLxG7TDes1GvNKsqhS6nyPczrhwKyLKo519SAp8iAcm6GT2W3owrxz6rPKdDdA5UE4gdG5o7roHhFG2TMEU7C3AZiwLSvdJcFksF2jKU6ZvdKBcrZd6bApthpuWbdPd7UJKgsx248QvxiyiE9uZ6rTB5HWinA5SJRRwNoLgvCgCLA6TMTqJ8aY9C2PDVcdV3KG3o9i6H5W181o5gMqaxctcEahWFVoonbR3sZmBCMg3vBGvEcm1WFANAM1X5uAHLgWhuLoRSG2jRgjJ5ZTbqystMvsu6MdeAUeRAYh1Wo8QKjX8hoTK7zg94mcb5rVEoJT4cEH2hCpRtviwGDs8yMsTubPBDPJJZCrxFQZdioWwViqhEjfJpdoT6ktt9TSxxRJUZa82vugKN1khxfGUubxrt68Y8ssfXK4Yx3xwWXSfXiphRjU18jCueUmJpMrX3mVqYSyjwwhbzvj2r8WoMCnF2YND7Nu71ptc3RVB73NqDzxd9WwBb84HGpedH47Tcv5P9XJ2Sj4e1CusMjKuMyyghQiAMT3iGA6d99nb9t7GTuGbmxuKsQV',
//   needles: [ 'abandon', 'bread', 'can' ]
// }

const secret = await decrypt(
  "grunt daisy chow barge pants",
  "PZE3jTZh45dkU6Du2H4T1j",
  "35Trmr54uFiqdd7xTs4iM7",
  "5fwe9NVe1omHDCWy5hPAk1Vne2XvwFCHAWBLjwxnFFFGm4tvhQVY55N9o5RnVGA1gd5EfX8xxWYZGxnbeUM9sqK8SzbCi2R5nA4K2zJ4oc4j6HFBiYkVq4JCfuAgoq2KwY1VSqtfBkcEMHqasDv263pbFdMQUiQDGDTCKZPCfDzqTUsFF19jKX51JPin8AxU7ywZ1vsWjLjmo41zVAX1jCLi1gDJ2bxupKeiKsrDvWgXXrkFpbC18CauJuFbbnuoMK3NP7m3itpRe3nfb4ZQNCGGv4JCv2cqpGdmhrXaVfKsP1zvjoNWbSJJPbhzGFJCgyvKsx4Aib3tpByXKkXJEQid27SNshPap2oD27LgnDraNDHgR9tD2euKj9nXFKcFQ22T6DwAqsFS34KVNzCHF6jF8oq9SHHCL2hhCnncgAweKyT8XEwnZBH8XzdJH36HqmpQrTu1V4xLxG7TDes1GvNKsqhS6nyPczrhwKyLKo519SAp8iAcm6GT2W3owrxz6rPKdDdA5UE4gdG5o7roHhFG2TMEU7C3AZiwLSvdJcFksF2jKU6ZvdKBcrZd6bApthpuWbdPd7UJKgsx248QvxiyiE9uZ6rTB5HWinA5SJRRwNoLgvCgCLA6TMTqJ8aY9C2PDVcdV3KG3o9i6H5W181o5gMqaxctcEahWFVoonbR3sZmBCMg3vBGvEcm1WFANAM1X5uAHLgWhuLoRSG2jRgjJ5ZTbqystMvsu6MdeAUeRAYh1Wo8QKjX8hoTK7zg94mcb5rVEoJT4cEH2hCpRtviwGDs8yMsTubPBDPJJZCrxFQZdioWwViqhEjfJpdoT6ktt9TSxxRJUZa82vugKN1khxfGUubxrt68Y8ssfXK4Yx3xwWXSfXiphRjU18jCueUmJpMrX3mVqYSyjwwhbzvj2r8WoMCnF2YND7Nu71ptc3RVB73NqDzxd9WwBb84HGpedH47Tcv5P9XJ2Sj4e1CusMjKuMyyghQiAMT3iGA6d99nb9t7GTuGbmxuKsQV",
  kdf,
  "bread" // One can optionally supply needle to significantly speed up decryption
)
// this is a test
// yo
```
