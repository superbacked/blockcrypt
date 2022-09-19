import { createCipheriv, createDecipheriv, randomBytes } from "crypto"

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
 * Get data length of message
 * @param message message
 * @returns data length
 */
export const getDataLength = (message: string) => {
  const key = randomBytes(32)
  const iv = randomBytes(12)
  const cipher = createCipheriv("aes-256-gcm", key, iv)
  const enciphered = cipher.update(message)
  const encipheredFinal = Buffer.concat([enciphered, cipher.final()])
  const authTag = cipher.getAuthTag()
  const buffer = Buffer.concat([encipheredFinal, iv, authTag])
  return buffer.toString("base64").length
}

/**
 * Encrypt secrets using Blockcrypt
 * @param secrets secrets
 * @param kdf key derivation function
 * @param headersLength optional, headers length in increments of 8 (defaults to 128)
 * @param dataLength optional, data length in increments of 8 (defaults to first secret ciphertext buffer length * 2 rounded to nearest upper increment of 128)
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
  if (!validateSecrets(secrets)) {
    throw new Error("Invalid secrets")
  }
  if (headersLength && headersLength % 8 !== 0) {
    throw new Error("Invalid headers length")
  } else if (!headersLength) {
    headersLength = 128
  }
  if (dataLength && dataLength % 8 !== 0) {
    throw new Error("Invalid data length")
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
    const dataIv = randomBytes(12)
    const dataCipher = createCipheriv("aes-256-gcm", key, dataIv)
    const dataEnciphered = dataCipher.update(secret.message)
    const dataEncipheredFinal = Buffer.concat([
      dataEnciphered,
      dataCipher.final(),
    ])
    const dataAuthTag = dataCipher.getAuthTag()
    const dataEncipheredFinalLength = dataEncipheredFinal.length
    const headersCipher = createCipheriv("aes-256-cbc", key, iv)
    const headersEnciphered = headersCipher.update(
      `${dataStart}:${dataEncipheredFinalLength}`
    )
    const headersEncipheredFinal = Buffer.concat([
      headersEnciphered,
      headersCipher.final(),
    ])
    headersBuffers.push(headersEncipheredFinal)
    const dataBuffer = Buffer.concat([dataEncipheredFinal, dataIv, dataAuthTag])
    dataBuffers.push(dataBuffer)
    dataStart += dataBuffer.length
    if (!dataLength && index === 0) {
      dataLength =
        Math.ceil((dataBuffer.toString("base64").length * 2) / 128) * 128
    }
  }
  let data = Buffer.concat(dataBuffers).toString("base64")
  const unpaddedDataLength = data.length
  if (unpaddedDataLength > dataLength) {
    throw new Error("Data too long for data length")
  }
  dataBuffers.push(randomBytes((dataLength - unpaddedDataLength) * 0.75))
  data = Buffer.concat(dataBuffers).toString("base64")
  let headers = Buffer.concat(headersBuffers).toString("base64")
  const unpaddedHeadersLength = headers.length
  if (unpaddedHeadersLength > headersLength) {
    throw new Error("Headers too long for headers length")
  }
  headersBuffers.push(
    randomBytes((headersLength - unpaddedHeadersLength) * 0.75)
  )
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
          "aes-256-cbc",
          key,
          Buffer.from(iv, "base64")
        )
        const headersDeciphered = headersDecipher.update(
          headersBuffer.subarray(headerStart, headerEnd)
        )
        const headerDecipheredFinal = Buffer.concat([
          headersDeciphered,
          headersDecipher.final(),
        ])
        const string = headerDecipheredFinal.toString()
        if (string.match(/^[0-9]+:[0-9]+$/)) {
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
  const [dataEncipheredFinalStart, dataEncipheredFinalLength] =
    header.split(":")
  const dataEncipheredFinalEnd =
    parseInt(dataEncipheredFinalStart) + parseInt(dataEncipheredFinalLength)
  const dataEncipheredFinal = dataBuffer.subarray(
    parseInt(dataEncipheredFinalStart),
    dataEncipheredFinalEnd
  )
  const dataIvStart = dataEncipheredFinalEnd
  const dataIvEnd = dataIvStart + 12
  const dataIv = dataBuffer.subarray(dataIvStart, dataIvEnd)
  const dataAuthTagStart = dataIvEnd
  const dataAuthTag = dataBuffer.subarray(
    dataAuthTagStart,
    dataAuthTagStart + 16
  )
  const dataDecipher = createDecipheriv("aes-256-gcm", key, dataIv)
  dataDecipher.setAuthTag(dataAuthTag)
  const dataDeciphered = dataDecipher.update(dataEncipheredFinal)
  const dataDecipheredFinal = Buffer.concat([
    dataDeciphered,
    dataDecipher.final(),
  ])
  const message = dataDecipheredFinal.toString()
  return message
}
