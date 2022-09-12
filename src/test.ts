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
const referenceNeedles = ["abandon", "bread", "can"]

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

test("fails to encrypt no secrets", async () => {
  expect.assertions(1)
  try {
    await encrypt([], insecureKdf)
  } catch (error) {
    expect(error.message).toEqual("Invalid secrets")
  }
})

test("fails to encrypt invalid secrets", async () => {
  expect.assertions(1)
  try {
    //@ts-ignore
    await encrypt([{ foo: "bar" }], insecureKdf)
  } catch (error) {
    expect(error.message).toEqual("Invalid secrets")
  }
})

test("fails to encrypt secrets using invalid negative block size", async () => {
  expect.assertions(1)
  try {
    await encrypt(secrets, insecureKdf, -1)
  } catch (error) {
    expect(error.message).toEqual("Invalid block size")
  }
})

test("fails to encrypt secrets using invalid positive block size", async () => {
  expect.assertions(1)
  try {
    await encrypt(secrets, insecureKdf, 4096)
  } catch (error) {
    expect(error.message).toEqual("Invalid block size")
  }
})

test("fails to encrypt secrets using fixed block size that is to small for secrets", async () => {
  expect.assertions(1)
  try {
    await encrypt(secrets, insecureKdf, 256)
  } catch (error) {
    expect(error.message).toEqual("Secrets too large for block size")
  }
})

test("fails to encrypt secrets using auto block size that is to small for secrets", async () => {
  expect.assertions(1)
  try {
    await encrypt(
      [].concat(
        ...secrets,
        {
          message:
            "apple detail zoo peanut plastic reject payment renew box coconut ivory media gold antique scorpion settle trip gaze rain slender sunny hidden mule old",
          passphrase: "tart equal payer early axis",
        },
        {
          message:
            "leaf spawn guitar immune diagram height flag once giant tell pepper sugar sphere stomach coach erase fatigue lens tunnel love range flight embark control",
          passphrase: "mate cedar brook flop snowy",
        }
      ),
      insecureKdf
    )
  } catch (error) {
    expect(error.message).toEqual("Secrets too large for block size")
  }
})

test("encrypts secrets and quickly decrypts secret 1 without needle", async () => {
  const block = await encrypt(secrets, insecureKdf)
  const secret = await decrypt(
    secrets[0].passphrase,
    block.salt,
    block.iv,
    block.ciphertext,
    insecureKdf
  )
  expect(secret).toEqual({
    message: secrets[0].message,
    needle: block.needles[0],
  })
})

test("encrypts secrets and quickly fails to decrypt secret 1 using invalid needle", async () => {
  expect.assertions(1)
  const block = await encrypt(secrets, insecureKdf)
  try {
    await decrypt(
      secrets[0].passphrase,
      block.salt,
      block.iv,
      block.ciphertext,
      insecureKdf,
      "yo"
    )
  } catch (error) {
    expect(error.message).toEqual("Needle not found")
  }
})

test("encrypts secrets and eventually fails to decrypt secret 1 using wrong needle", async () => {
  expect.assertions(1)
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
  expect(secret).toEqual({
    message: secrets[1].message,
    needle: block.needles[1],
  })
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
  expect(secret).toEqual({
    message: secrets[1].message,
    needle: block.needles[1],
  })
})
