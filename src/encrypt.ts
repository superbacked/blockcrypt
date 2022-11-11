import { encryptCBC, encryptGCM, randomBytes } from "./crypto"
import { Block, BufferBlock, Kdf, Secret } from "./types"
import { concat, isWebEnvironment, toBase64, toUint8Array } from "./util"

const isValidSecrets = (secrets: Secret[]): boolean =>
  secrets instanceof Array &&
  secrets.length > 0 &&
  secrets.every(
    (secret) =>
      toUint8Array(secret.message || "").byteLength > 0 &&
      (secret.passphrase || "").length > 0
  )

const encryptData = async (key: Uint8Array, secret: Secret) => {
  const iv = await randomBytes(12)
  const { ciphertext, authTag } = await encryptGCM(
    key,
    iv,
    toUint8Array(secret.message)
  )
  return { ciphertext, iv, authTag }
}

const encryptHeader = (key: Uint8Array, block: Block, ciphertext: Uint8Array) =>
  encryptCBC(
    key,
    block.iv,
    toUint8Array(`${block.data.byteLength}:${ciphertext.byteLength}`)
  )

const padBytes = async (
  buffer: Uint8Array,
  desiredLength: number,
  errorMessage: string
): Promise<Uint8Array> => {
  if (buffer.byteLength > desiredLength) {
    throw new Error(errorMessage)
  }
  return randomBytes(desiredLength - buffer.byteLength)
}

const padData = (data: Uint8Array, dataLength: number) =>
  padBytes(data, dataLength, "Data too long for data length")

const padHeaders = (headers: Uint8Array, headersLength: number) =>
  padBytes(headers, headersLength, "Headers too long for headers length")

const encryptSecret = async (
  kdf: Kdf,
  secret: Secret,
  block: Block,
  secretsIndex: number,
  secretsLength: number,
  headersLength: number,
  dataLength: number
): Promise<Block> => {
  const key = await kdf(secret.passphrase, toBase64(block.salt))
  const { ciphertext, iv, authTag } = await encryptData(key, secret)
  const headers = concat([
    block.headers,
    await encryptHeader(key, block, ciphertext),
  ])
  const data = concat([block.data, ciphertext, iv, authTag])
  const isLastIndex = secretsIndex + 1 === secretsLength
  return {
    ...block,
    data: isLastIndex ? concat([data, await padData(data, dataLength)]) : data,
    headers: isLastIndex
      ? concat([headers, await padHeaders(headers, headersLength)])
      : headers,
  }
}

const encryptSecrets = (
  secrets: Secret[],
  kdf: Kdf,
  salt: Uint8Array,
  iv: Uint8Array,
  headersLength: number,
  dataLength?: number
) => {
  return secrets.reduce(
    async (promise: Promise<Block>, secret: Secret, index) => {
      const previousBlock = await promise
      const block = await encryptSecret(
        kdf,
        secret,
        previousBlock,
        index,
        secrets.length,
        headersLength,
        dataLength
      )
      if (!dataLength && index === 0) {
        dataLength = Math.ceil((block.data.byteLength * 2) / 64) * 64
      }
      return block
    },
    Promise.resolve({
      data: Uint8Array.from([]),
      headers: Uint8Array.from([]),
      salt,
      iv,
    })
  )
}

const createBufferBlock = (block: Block): BufferBlock => ({
  salt: Buffer.from(block.salt),
  iv: Buffer.from(block.iv),
  headers: Buffer.from(block.headers),
  data: Buffer.from(block.data),
})

/**
 * Encrypt secrets using Blockcrypt
 * @param secrets secrets
 * @param kdf key derivation function
 * @param headersLength optional, headers length in increments of `8` bytes (defaults to `64`)
 * @param dataLength optional, data length in increments of `8` bytes (defaults to first secret ciphertext buffer length * 2 rounded to nearest upper increment of `64` bytes)
 * @param salt optional, salt used for deterministic unit tests
 * @param iv optional, initialization vector used for deterministic unit tests
 * @returns block
 */
const encrypt = async (
  secrets: Secret[],
  kdf: Kdf,
  headersLength?: number,
  dataLength?: number,
  salt?: Uint8Array,
  iv?: Uint8Array
): Promise<Block | BufferBlock> => {
  if (!isValidSecrets(secrets)) {
    throw new Error("Invalid secrets")
  }
  if (headersLength && headersLength % 8 !== 0) {
    throw new Error("Invalid headers length")
  } else if (!headersLength) {
    headersLength = 64
  }
  if (dataLength && dataLength % 8 !== 0) {
    throw new Error("Invalid data length")
  }
  const block = await encryptSecrets(
    secrets,
    kdf,
    salt || (await randomBytes(16)),
    iv || (await randomBytes(16)),
    headersLength,
    dataLength
  )
  return isWebEnvironment() ? block : createBufferBlock(block)
}

export default encrypt
