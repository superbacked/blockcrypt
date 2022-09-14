import { createCipheriv, createDecipheriv, randomBytes } from "crypto"

const algorithm = "aes-256-cbc"

export interface Secret {
  message: string
  passphrase: string
}

export type Kdf = (passphrase: string, salt?: string) => Promise<Buffer>

export interface Block {
  salt: string
  iv: string
  headers: string
  data: string
}

const validateSecrets = (secrets: Secret[]) => {
  if (!(secrets instanceof Array) || secrets.length === 0) {
    return false
  }
  for (const secret of secrets) {
    if (!secret.message || !secret.passphrase) {
      return false
    }
  }
  return true
}

/**
 * Get block size for message
 * @param message message
 * @returns block size
 */
export const getBlockSize = (message: string) => {
  const buffer = Buffer.from(message)
  // Simulate AES-256-CBC
  const encryptedBufferLength = Math.ceil(buffer.length / 16) * 16
  // Simulate Base64
  const base64Length = ((4 * encryptedBufferLength) / 3 + 3) & ~3
  return base64Length
}

/**
 * Encrypt secrets using Blockcrypt
 * @param secrets secrets
 * @param kdf key derivation function
 * @param headersSize optional, headers size in increments of 8 (defaults to 128)
 * @param dataSize optional, data size in increments of 8 (defaults to first secret ciphertext buffer size * 2 rounded to nearest upper increment of 128)
 * @param salt optional, salt used for deterministic unit tests
 * @param iv optional, initialization vector used for deterministic unit tests
 * @returns block
 */
export const encrypt = async (
  secrets: Secret[],
  kdf: Kdf,
  headersSize?: number,
  dataSize?: number,
  salt?: Buffer,
  iv?: Buffer
): Promise<Block> => {
  if (!validateSecrets(secrets)) {
    throw new Error("Invalid secrets")
  }
  if (headersSize && headersSize % 8 !== 0) {
    throw new Error("Invalid headers size")
  } else if (!headersSize) {
    headersSize = 128
  }
  if (dataSize && dataSize % 8 !== 0) {
    throw new Error("Invalid data size")
  }
  if (!salt) {
    salt = randomBytes(16)
  }
  if (!iv) {
    iv = randomBytes(16)
  }
  let headersBuffers: Buffer[] = []
  let dataBuffers: Buffer[] = []
  let dataStart = 0
  for (const [index, secret] of secrets.entries()) {
    const key = await kdf(secret.passphrase, salt.toString("base64"))
    const dataCipher = createCipheriv(algorithm, key, iv)
    const dataEncrypted = dataCipher.update(secret.message)
    const dataBuffer = Buffer.concat([dataEncrypted, dataCipher.final()])
    const dataBufferLength = dataBuffer.length
    const headersCipher = createCipheriv(algorithm, key, iv)
    const headersEncrypted = headersCipher.update(
      `${dataStart}:${dataBufferLength}`
    )
    const headersBuffer = Buffer.concat([
      headersEncrypted,
      headersCipher.final(),
    ])
    headersBuffers.push(headersBuffer)
    dataBuffers.push(dataBuffer)
    dataStart += dataBufferLength
    if (!dataSize && index === 0) {
      dataSize =
        Math.ceil((dataBuffers[0].toString("base64").length * 2) / 128) * 128
    }
  }
  let data = Buffer.concat(dataBuffers).toString("base64")
  const dataLength = data.length
  if (dataLength > dataSize) {
    throw new Error("Data too large for data size")
  }
  dataBuffers.push(randomBytes((dataSize - dataLength) * 0.75))
  data = Buffer.concat(dataBuffers).toString("base64")
  let headers = Buffer.concat(headersBuffers).toString("base64")
  const headersLength = headers.length
  if (headersLength > headersSize) {
    throw new Error("Headers too large for headers size")
  }
  headersBuffers.push(randomBytes((headersSize - headersLength) * 0.75))
  headers = Buffer.concat(headersBuffers).toString("base64")
  return {
    salt: salt.toString("base64"),
    iv: iv.toString("base64"),
    headers: headers,
    data: data,
  }
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
  salt: string,
  iv: string,
  headers: string,
  data: string,
  kdf: Kdf
): Promise<string> => {
  const key = await kdf(passphrase, salt)
  const headersBuffer = Buffer.from(headers, "base64")
  const dataBuffer = Buffer.from(data, "base64")
  let headerStart = 0
  let header: string | null = null
  while (headerStart < headersBuffer.length) {
    for (
      let headerEnd = headersBuffer.length;
      headerEnd > headerStart;
      headerEnd--
    ) {
      try {
        const headersDecipher = createDecipheriv(
          algorithm,
          key,
          Buffer.from(iv, "base64")
        )
        const headersDecrypted = headersDecipher.update(
          headersBuffer.subarray(headerStart, headerEnd)
        )
        const headerBuffer = Buffer.concat([
          headersDecrypted,
          headersDecipher.final(),
        ])
        const string = headerBuffer.toString()
        if (!string.match(/�/)) {
          header = string
        }
        if (header) {
          break
        }
      } catch (error) {}
    }
    if (header) {
      break
    }
    headerStart++
  }
  if (!header) {
    throw new Error("Header not found")
  }
  try {
    const dataDecipher = createDecipheriv(
      algorithm,
      key,
      Buffer.from(iv, "base64")
    )
    const [dataStart, dataLength] = header.split(":")
    const dataDecrypted = dataDecipher.update(
      dataBuffer.subarray(
        parseInt(dataStart),
        parseInt(dataStart) + parseInt(dataLength)
      )
    )
    const headerBuffer = Buffer.concat([dataDecrypted, dataDecipher.final()])
    const secret = headerBuffer.toString()
    if (!secret) {
      throw new Error("Secret not found")
    }
    return secret
  } catch (error) {}
}
