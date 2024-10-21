import { createHmac } from "crypto"
import { decrypt, encrypt, getDataLength, Secret } from "./index"

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

const insecureKdf = async (
  passphrase: string,
  salt: string,
): Promise<Buffer> => {
  const hmac = createHmac("sha256", salt)
  const data = hmac.update(passphrase)
  return Buffer.from(data.digest("base64"), "base64")
}

test("gets data length of secret 1 as string", async () => {
  const dataLength = getDataLength(secrets[0].message)
  expect(dataLength).toEqual(172)
})

test("gets data length of secret 1 as buffer", async () => {
  const dataLength = getDataLength(Buffer.from(secrets[0].message))
  expect(dataLength).toEqual(172)
})

test("fails to encrypt no secrets", async () => {
  expect.assertions(1)
  try {
    await encrypt([], insecureKdf, 1024)
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

test("fails to encrypt secrets using block size that is too short", async () => {
  expect.assertions(1)
  try {
    await encrypt(secrets, insecureKdf, 32)
  } catch (error) {
    expect(error.message).toEqual("Block size exceeded")
  }
})

test("encrypts secret 1 using minimum required block size", async () => {
  const secret1 = secrets[0]
  const blockSize = 16 + 24 + Math.ceil(getDataLength(secret1.message) / 8) * 8
  const block = await encrypt([secret1], insecureKdf, blockSize)
  expect(block.byteLength).toBe(blockSize)
})

test("encrypts secrets using larger than required data length", async () => {
  const blockSize = 1024
  const block = await encrypt(secrets, insecureKdf, blockSize)
  expect(block.byteLength).toEqual(blockSize)
})

test("encrypts secrets and fails to decrypt secret 1 using wrong passphrase", async () => {
  expect.assertions(1)
  try {
    const block = await encrypt(secrets, insecureKdf, 1024)
    await decrypt(
      "foo",
      block,
      insecureKdf,
    )
  } catch (error) {
    expect(error.message).toEqual("Decryption failed")
  }
})

test("encrypts secrets and decrypts secret 1", async () => {
  const block = await encrypt([secrets[0]], insecureKdf, 256)
  const secret = await decrypt(
    secrets[0].passphrase,
    block,
    insecureKdf,
  )
  expect(secret.toString()).toEqual(secrets[0].message)
})

test("encrypts secrets and decrypts secret 2", async () => {
  const block = await encrypt(secrets, insecureKdf, 1024)
  const secret = await decrypt(
    secrets[1].passphrase,
    block,
    insecureKdf,
  )
  expect(secret.toString()).toEqual(secrets[1].message)
})

test("encrypts secrets and decrypts secret 3", async () => {
  const block = await encrypt(secrets, insecureKdf, 1024)
  const secret = await decrypt(
    secrets[2].passphrase,
    block,
    insecureKdf,
  )
  expect(secret).toEqual(secrets[2].message)
})
