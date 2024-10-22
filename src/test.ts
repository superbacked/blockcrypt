import { createHmac, randomBytes } from "node:crypto"
import { decrypt, deriveSecretKey, encrypt, Secret } from "./index"

const secrets: Secret[] = [
  {
    message:
      "trust vast puppy supreme public course output august glimpse reunion kite rebel virus tail pass enhance divorce whip edit skill dismiss alpha divert ketchup",
    key: Buffer.from([
      4, 72, 156, 132, 66, 216, 156, 26, 55, 162, 221, 77, 214, 13, 146, 94,
      146, 239, 47, 156, 123, 68, 210, 35, 142, 146, 52, 193, 214, 82, 109, 220,
    ]),
  },
  {
    message: "this is a test\nyo",
    key: Buffer.from([
      158, 198, 159, 43, 229, 18, 213, 1, 55, 116, 184, 62, 75, 237, 50, 184,
      123, 168, 31, 97, 208, 209, 209, 238, 42, 139, 98, 45, 31, 146, 7, 56,
    ]),
  },
  {
    message: Buffer.from("yo"),
    key: Buffer.from([
      180, 252, 249, 18, 136, 98, 214, 30, 168, 200, 64, 253, 65, 47, 210, 164,
      66, 60, 44, 101, 109, 239, 173, 17, 50, 217, 41, 106, 3, 129, 59, 132,
    ]),
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

const referenceSignature = Buffer.from(
  "Uk/QT5czNiRuYgceCkwkzUJ4TEuZbANzI97qRS/Wf/Tvu86ghuWUKZlTz60ibuswMlTQNvbqjrMUiUV8kiZ7sQ==",
  "base64",
)

test("confirms block matches reference", async () => {
  const block = await encrypt(secrets, 1024)
  expect(Buffer.compare(block.subarray(0, 64), referenceSignature)).toEqual(0)
})

test("fails to encrypt no secrets", async () => {
  expect.assertions(1)
  try {
    await encrypt([], 1024)
  } catch (error) {
    expect(error.message).toEqual("Invalid secrets")
  }
})

test("fails to encrypt invalid secrets", async () => {
  expect.assertions(1)
  try {
    //@ts-ignore
    await encrypt([{ foo: "bar" }], 1024)
  } catch (error) {
    expect(error.message).toEqual("Invalid secrets")
  }
})

test("fails to encrypt secrets using block size that is too short", async () => {
  expect.assertions(1)
  try {
    await encrypt(secrets, 32)
  } catch (error) {
    expect(error.message).toEqual("Block size exceeded")
  }
})

test("encrypts secret 1 using minimum required block size", async () => {
  const secret1 = secrets[0]
  const blockSize = 24 + Math.ceil(secret1.message.length / 8) * 8 + 16
  const block = await encrypt([secret1], blockSize)
  expect(block.byteLength).toBe(blockSize)
})

test("encrypts secrets using larger than required block size", async () => {
  const blockSize = 1024
  const block = await encrypt(secrets, blockSize)
  expect(block.byteLength).toEqual(blockSize)
})

test("encrypts secrets and fails to decrypt secret 1 using wrong key", async () => {
  expect.assertions(1)
  try {
    const block = await encrypt(secrets, 1024)
    await decrypt(Buffer.alloc(32), block)
  } catch (error) {
    expect(error.message).toEqual("Decryption failed")
  }
})

test("encrypts secrets and decrypts secret 1", async () => {
  const block = await encrypt(secrets.slice(0, 1), 256)
  const secret = await decrypt(secrets[0].key, block)
  expect(secret.toString()).toEqual(secrets[0].message)
})

test("encrypts secrets and decrypts secret 2", async () => {
  const block = await encrypt(secrets, 1024)
  const secret = await decrypt(secrets[1].key, block)
  expect(secret.toString()).toEqual(secrets[1].message)
})

test("encrypts secrets and decrypts secret 3", async () => {
  const block = await encrypt(secrets, 1024)
  const secret = await decrypt(secrets[2].key, block)
  expect(secret).toEqual(secrets[2].message)
})

test("derives secret key from passphrase", async () => {
  const passphrase = "decor gooey wish kept pug"
  const salt = randomBytes(16)
  const key = await deriveSecretKey(insecureKdf, passphrase, salt)
  expect(key).toBeInstanceOf(Buffer)
  expect(key.byteLength).toBe(32)
  expect(key).not.toEqual(Buffer.alloc(32))
})
