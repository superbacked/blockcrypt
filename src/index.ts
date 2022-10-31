import {
  decryptCBC,
  decryptGCM,
  encryptCBC,
  encryptGCM,
  randomBytes,
} from "./crypto"
import { concat, toBase64, toUint8Array, toUTF8String } from "./util"

export type Message = Uint8Array | string

export interface Secret {
  message: Message
  passphrase: string
}

export type Kdf = (passphrase: string, salt: string) => Promise<Uint8Array>

export interface Block {
  salt: Uint8Array
  iv: Uint8Array
  headers: Uint8Array
  data: Uint8Array
}

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

/**
 * Get data length of message
 * @param message message
 * @returns data length in bytes
 */
export const getDataLength = (message: Message) =>
  toUint8Array(message).byteLength + 12 + 16

/**
 * Encrypt secrets using Blockcrypt
 * @param secrets secrets
 * @param kdf key derivation function
 * @param headersLength optional, headers length in increments of `8` bytes (defaults to `64`)
 * @param dataLength optional, data length in increments of `8` bytes (defaults to first secret ciphertext Uint8Array length * 2 rounded to nearest upper increment of `64` bytes)
 * @param salt optional, salt used for deterministic unit tests
 * @param iv optional, initialization vector used for deterministic unit tests
 * @returns block
 */
export const encrypt = async (
  secrets: Secret[],
  kdf: Kdf,
  headersLength?: number,
  dataLength?: number,
  salt?: Uint8Array,
  iv?: Uint8Array
): Promise<Block> => {
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
      salt: salt || (await randomBytes(16)),
      iv: iv || (await randomBytes(16)),
    })
  )
}

const createRange = (start: number, end: number) =>
  [...Array(end - start + 1).keys()].map((x) => x + start)

const createHeaderRanges = (headers: Uint8Array) => {
  const ranges = createRange(0, headers.byteLength)
  return ranges
    .map((start) =>
      ranges
        .map((end) => ({ start, end }))
        .filter(({ start, end }) => end - start > 0)
        .reverse()
    )
    .flat()
}

const decryptHeader = async (
  key: Uint8Array,
  iv: Uint8Array,
  headers: Uint8Array,
  start: number,
  end: number
) => toUTF8String(await decryptCBC(key, iv, headers.subarray(start, end)))

const decryptHeaders = async (
  key: Uint8Array,
  iv: Uint8Array,
  headers: Uint8Array
) => {
  const result = await createHeaderRanges(headers).reduce(
    async (promise, { start, end }) => {
      const header = await promise
      if (header) {
        return header
      }
      try {
        const string = await decryptHeader(key, iv, headers, start, end)
        if (string.match(/^[0-9]+:[0-9]+$/)) {
          return string
        }
      } catch (error) {}
      return header
    },
    Promise.resolve("")
  )
  if (!result) {
    throw new Error("Header not found")
  }
  const [dataStart, dataSize] = result.split(":").map((str) => parseInt(str))
  return [dataStart, dataStart + dataSize]
}

const decryptData = (
  key: Uint8Array,
  data: Uint8Array,
  ciphertextStart: number,
  ciphertextEnd: number
) => {
  const ciphertext = data.subarray(ciphertextStart, ciphertextEnd)
  const ivEnd = ciphertextEnd + 12
  const iv = data.subarray(ciphertextEnd, ivEnd)
  const authTag = data.subarray(ivEnd, ivEnd + 16)
  return decryptGCM(key, iv, ciphertext, authTag)
}

/**
 * Decrypt secret encrypted using Blockcrypt
 * @param passphrase passphrase
 * @param salt salt
 * @param iv initialization vector
 * @param headers headers
 * @param data data
 * @param kdf key derivation function
 * @returns message
 */
export const decrypt = async (
  passphrase: string,
  salt: Uint8Array,
  iv: Uint8Array,
  headers: Uint8Array,
  data: Uint8Array,
  kdf: Kdf
): Promise<Uint8Array> => {
  const key = await kdf(passphrase, toBase64(salt))
  const [dataStart, dataEnd] = await decryptHeaders(key, iv, headers)
  return decryptData(key, data, dataStart, dataEnd)
}
