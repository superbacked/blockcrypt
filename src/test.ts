import { createHash } from "crypto"
import { encrypt, decrypt, getBlockSize, Secret } from "./index"

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

const insecureKdf = async (passphrase: string) => {
  const hash = createHash("sha256")
  const data = hash.update(passphrase)
  return Buffer.from(data.digest("base64"), "base64")
}

const referenceSalt = "Com4/aFtBjaGdvbjgi5UNw=="
const referenceSaltBuffer = Buffer.from(referenceSalt, "base64")
const referenceIv = "u05uhhQe3NDtCf39rsxnig=="
const referenceIvBuffer = Buffer.from(referenceIv, "base64")
const referenceHeadersSignature = "ZYtwLEiUAXh+BCO31dT79JrK"
const referenceDataSignature = "FgsCYmyDsw1Sk3RzVFxml+Ys"

test("gets block size of secret 1", async () => {
  const blockSize = getBlockSize(secrets[0].message)
  expect(blockSize).toEqual(216)
})

test("confirms block matches reference", async () => {
  const block = await encrypt(
    secrets,
    insecureKdf,
    null,
    null,
    referenceSaltBuffer,
    referenceIvBuffer
  )
  expect(block.salt).toEqual(referenceSalt)
  expect(block.iv).toEqual(referenceIv)
  expect(block.headers.length).toEqual(128)
  expect(block.headers.substring(0, 24)).toEqual(referenceHeadersSignature)
  expect(block.data.length).toEqual(512)
  expect(block.data.substring(0, 24)).toEqual(referenceDataSignature)
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

test("fails to encrypt secrets using invalid headers size", async () => {
  expect.assertions(1)
  try {
    await encrypt(secrets, insecureKdf, 127)
  } catch (error) {
    expect(error.message).toEqual("Invalid headers size")
  }
})

test("fails to encrypt secrets using headers size that is to small for headers", async () => {
  expect.assertions(1)
  try {
    await encrypt(secrets, insecureKdf, 32)
  } catch (error) {
    expect(error.message).toEqual("Headers too large for headers size")
  }
})

test("fails to encrypt secrets using default headers size that is to small for headers", async () => {
  expect.assertions(1)
  try {
    await encrypt(
      [].concat(
        ...secrets,
        {
          message: "one",
          passphrase: "mousy ditch pull prize stall",
        },
        {
          message: "two",
          passphrase: "lurk entry clip tidal cinch",
        },
        {
          message: "three",
          passphrase: "geek skid last stays shout",
        },
        {
          message: "four",
          passphrase: "aroma feed user wing darn",
        }
      ),
      insecureKdf
    )
  } catch (error) {
    expect(error.message).toEqual("Headers too large for headers size")
  }
})

test("encrypts secrets using unusual but valid headers size", async () => {
  const headersSize = 120
  const block = await encrypt(secrets, insecureKdf, headersSize)
  expect(block.headers.length).toEqual(headersSize)
})

test("fails to encrypt secret 1 using invalid data size", async () => {
  expect.assertions(1)
  try {
    const secret1 = secrets[0]
    const blockSize = getBlockSize(secret1.message)
    await encrypt([secret1], insecureKdf, null, blockSize - 1)
  } catch (error) {
    expect(error.message).toEqual("Invalid data size")
  }
})

test("fails to encrypt secret 1 using minimum required data size minus 8", async () => {
  expect.assertions(1)
  try {
    const secret1 = secrets[0]
    const blockSize = getBlockSize(secret1.message)
    await encrypt([secret1], insecureKdf, 128, blockSize - 8)
  } catch (error) {
    expect(error.message).toEqual("Data too large for data size")
  }
})

test("fails to encrypt secrets using data size that is to small for data", async () => {
  expect.assertions(1)
  try {
    await encrypt(secrets, insecureKdf, null, 256)
  } catch (error) {
    expect(error.message).toEqual("Data too large for data size")
  }
})

test("fails to encrypt secrets using auto data size that is to small for data", async () => {
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
    expect(error.message).toEqual("Data too large for data size")
  }
})

test("encrypts secret 1 using minimum required data size", async () => {
  const secret1 = secrets[0]
  const blockSize = getBlockSize(secret1.message)
  const block = await encrypt([secret1], insecureKdf, 128, blockSize)
  expect(block).toBeDefined()
})

test("encrypts secrets using unusual but valid data size", async () => {
  const dataSize = 1016
  const block = await encrypt(secrets, insecureKdf, null, dataSize)
  expect(block.data.length).toEqual(dataSize)
})

test("encrypts secrets and fails to decrypt secret 1 using wrong passphrase", async () => {
  expect.assertions(1)
  try {
    const block = await encrypt(secrets, insecureKdf)
    await decrypt(
      "foo",
      block.salt,
      block.iv,
      block.headers,
      block.data,
      insecureKdf
    )
  } catch (error) {
    expect(error.message).toEqual("Header not found")
  }
})

test("encrypts secrets and decrypts secret 1", async () => {
  const block = await encrypt(secrets, insecureKdf)
  const secret = await decrypt(
    secrets[0].passphrase,
    block.salt,
    block.iv,
    block.headers,
    block.data,
    insecureKdf
  )
  expect(secret).toEqual(secrets[0].message)
})

test("encrypts secrets and decrypts secret 2", async () => {
  const block = await encrypt(secrets, insecureKdf)
  const secret = await decrypt(
    secrets[1].passphrase,
    block.salt,
    block.iv,
    block.headers,
    block.data,
    insecureKdf
  )
  expect(secret).toEqual(secrets[1].message)
})

test("encrypts secrets and decrypts secret 3", async () => {
  const block = await encrypt(secrets, insecureKdf)
  const secret = await decrypt(
    secrets[2].passphrase,
    block.salt,
    block.iv,
    block.headers,
    block.data,
    insecureKdf
  )
  expect(secret).toEqual(secrets[2].message)
})
