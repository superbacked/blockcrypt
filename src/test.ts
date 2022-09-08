import { createHash } from "crypto"
import { decode } from "bs58"
import { encrypt, decrypt, Secret } from "./index"

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

const insecureKdf = async (passphrase: string) => {
  const hash = createHash("sha256")
  const data = hash.update(passphrase)
  return data.digest("hex")
}

const referenceSaltBuffer = Buffer.from(decode("PZE3jTZh45dkU6Du2H4T1j"))
const referenceIvBuffer = Buffer.from(decode("35Trmr54uFiqdd7xTs4iM7"))
const referenceCiphertextSignature =
  "5fwe9NVe1omHDCWy5hPAk1Vne2XvwFCHAWBLjwxnFFFGm4tvhQVY55N9o5RnVGA1"
const referenceNeedles = ["acid", "cold", "curry"]

test("confirms block matches reference", async () => {
  const block = await encrypt(
    secrets,
    insecureKdf,
    1024,
    referenceSaltBuffer,
    referenceIvBuffer
  )
  expect(block.salt).toEqual("PZE3jTZh45dkU6Du2H4T1j")
  expect(block.iv).toEqual("35Trmr54uFiqdd7xTs4iM7")
  expect(block.ciphertext.substring(0, 64)).toEqual(
    referenceCiphertextSignature
  )
  expect(block.needles).toEqual(referenceNeedles)
})

test("fails to encrypt secrets using block size that is to small", async () => {
  try {
    await encrypt(secrets, insecureKdf, 256)
  } catch (error) {
    expect(error.message).toEqual("Secrets too large for block size")
  }
})

test("encrypts secrets and quicly decrypts secret 1 without needle", async () => {
  const block = await encrypt(secrets, insecureKdf, 1024)
  const secret = await decrypt(
    secrets[0].passphrase,
    block.salt,
    block.iv,
    block.ciphertext,
    insecureKdf
  )
  expect(secret).toEqual(secrets[0].message)
})

test("encrypts secrets and eventually fails to decrypt secret 1 using wrong needle", async () => {
  const block = await encrypt(secrets, insecureKdf)
  try {
    await decrypt(
      secrets[0].passphrase,
      block.salt,
      block.iv,
      block.ciphertext,
      insecureKdf,
      block.needles[1]
    )
  } catch (error) {
    expect(error.message).toEqual("Secret not found")
  }
})

test("encrypt secrets and eventually decrypts secret 2 without needle", async () => {
  const block = await encrypt(secrets, insecureKdf)
  const secret = await decrypt(
    secrets[1].passphrase,
    block.salt,
    block.iv,
    block.ciphertext,
    insecureKdf
  )
  expect(secret).toEqual(secrets[1].message)
})

test("encrypt secrets and quickly decrypts secret 2 using needle", async () => {
  const block = await encrypt(secrets, insecureKdf)
  const secret = await decrypt(
    secrets[1].passphrase,
    block.salt,
    block.iv,
    block.ciphertext,
    insecureKdf,
    block.needles[1]
  )
  expect(secret).toEqual(secrets[1].message)
})
