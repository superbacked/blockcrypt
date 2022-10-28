import { createCipheriv, createDecipheriv, randomBytes } from "crypto"

export type Message = Buffer | string

export interface Secret {
  message: Message
  passphrase: string
}

export type Kdf = (passphrase: string, salt: string) => Promise<Buffer>

export interface Block {
  salt: Buffer
  iv: Buffer
  headers: Buffer
  data: Buffer
}

const isValidSecrets = (secrets: Secret[]): boolean =>
  secrets instanceof Array &&
  secrets.length > 0 &&
  secrets.every(
    (secret) =>
      Buffer.from(secret.message || "").byteLength > 0 &&
      (secret.passphrase || "").length > 0
  )

const encryptData = (key: Buffer, secret: Secret) => {
  const iv = randomBytes(12)
  const cipher = createCipheriv("aes-256-gcm", key, iv)
  const ciphertext = Buffer.concat([
    cipher.update(secret.message),
    cipher.final(),
  ])
  const authTag = cipher.getAuthTag()
  return { ciphertext, iv, authTag }
}

const encryptHeader = (key: Buffer, block: Block, ciphertext: Buffer) => {
  const cipher = createCipheriv("aes-256-cbc", key, block.iv)
  return Buffer.concat([
    cipher.update(`${block.data.byteLength}:${ciphertext.byteLength}`),
    cipher.final(),
  ])
}

const padBytes = (
  buffer: Buffer,
  desiredLength: number,
  errorMessage: string
): Buffer => {
  if (buffer.byteLength > desiredLength) {
    throw new Error(errorMessage)
  }
  return randomBytes(desiredLength - buffer.byteLength)
}

const padData = (data: Buffer, dataLength: number) =>
  padBytes(data, dataLength, "Data too long for data length")

const padHeaders = (headers: Buffer, headersLength: number) =>
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
  const key = await kdf(secret.passphrase, block.salt.toString("base64"))
  const { ciphertext, iv, authTag } = encryptData(key, secret)
  const headers = Buffer.concat([
    block.headers,
    encryptHeader(key, block, ciphertext),
  ])
  const data = Buffer.concat([block.data, ciphertext, iv, authTag])
  const isLastIndex = secretsIndex + 1 === secretsLength
  return {
    ...block,
    data: isLastIndex ? Buffer.concat([data, padData(data, dataLength)]) : data,
    headers: isLastIndex
      ? Buffer.concat([headers, padHeaders(headers, headersLength)])
      : headers,
  }
}

/**
 * Get data length of message
 * @param message message
 * @returns data length in bytes
 */
export const getDataLength = (message: Message) =>
  Buffer.from(message).byteLength + 12 + 16

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
export const encrypt = async (
  secrets: Secret[],
  kdf: Kdf,
  headersLength?: number,
  dataLength?: number,
  salt?: Buffer,
  iv?: Buffer
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
      data: Buffer.from([]),
      headers: Buffer.from([]),
      salt: salt || randomBytes(16),
      iv: iv || randomBytes(16),
    })
  )
}

const createRange = (start: number, end: number) =>
  [...Array(end - start + 1).keys()].map((x) => x + start)

const createHeaderRanges = (headers: Buffer) => {
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

const decryptHeader = (
  key: Buffer,
  iv: Buffer,
  headers: Buffer,
  start: number,
  end: number
) => {
  const decipher = createDecipheriv("aes-256-cbc", key, iv)
  const header = decipher.update(headers.subarray(start, end))
  return Buffer.concat([header, decipher.final()]).toString()
}

const decryptHeaders = (key: Buffer, iv: Buffer, headers: Buffer) => {
  let header = ""
  createHeaderRanges(headers).every(({ start, end }) => {
    try {
      const string = decryptHeader(key, iv, headers, start, end)
      if (string.match(/^[0-9]+:[0-9]+$/)) {
        header = string
        return false
      }
    } catch (error) {}
    return true
  })
  if (!header) {
    throw new Error("Header not found")
  }
  const [dataStart, dataSize] = header.split(":").map((str) => parseInt(str))
  return [dataStart, dataStart + dataSize]
}

const decryptData = (
  key: Buffer,
  data: Buffer,
  ciphertextStart: number,
  ciphertextEnd: number
) => {
  const ciphertext = data.subarray(ciphertextStart, ciphertextEnd)
  const ivEnd = ciphertextEnd + 12
  const iv = data.subarray(ciphertextEnd, ivEnd)
  const authTag = data.subarray(ivEnd, ivEnd + 16)
  const decipher = createDecipheriv("aes-256-gcm", key, iv).setAuthTag(authTag)
  return Buffer.concat([decipher.update(ciphertext), decipher.final()])
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
  salt: Buffer,
  iv: Buffer,
  headers: Buffer,
  data: Buffer,
  kdf: Kdf
): Promise<Buffer> => {
  const key = await kdf(passphrase, salt.toString("base64"))
  const [dataStart, dataEnd] = decryptHeaders(key, iv, headers)
  return decryptData(key, data, dataStart, dataEnd)
}
