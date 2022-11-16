import { GCM_IV_LENGTH, GCM_TAG_LENGTH } from "./constants"
import { decryptCBC, decryptGCM } from "./crypto"
import { Kdf } from "./types"
import { isWebEnv, toHexString, toUTF8String } from "./util"

const createHeaderRange = (start: number, end: number) =>
  [...Array(end - start + 1).keys()].map((x) => x + start)

const createHeaderRanges = (headers: Uint8Array) => {
  const ranges = createHeaderRange(0, headers.byteLength)
  return ranges
    .map((start) =>
      ranges
        .map((end) => ({ start, end }))
        .filter(({ start, end }) => end - start > 0)
        .reverse()
    )
    .flat()
}

const decryptHeaderRange = async (
  key: Uint8Array,
  iv: Uint8Array,
  headers: Uint8Array,
  start: number,
  end: number
) => {
  try {
    const headerBytes = await decryptCBC(key, iv, headers.subarray(start, end))
    const header = toUTF8String(headerBytes)
    if (header.match(/^[0-9]+:[0-9]+$/)) {
      return header
    }
  } catch (error) {}
  return ""
}

const decryptHeaderRanges = async (
  key: Uint8Array,
  iv: Uint8Array,
  headers: Uint8Array
) =>
  createHeaderRanges(headers).reduce(async (promise, { start, end }) => {
    const header = await promise
    if (header) {
      return header
    }
    return decryptHeaderRange(key, iv, headers, start, end)
  }, Promise.resolve(""))

const decryptHeaders = async (
  key: Uint8Array,
  iv: Uint8Array,
  headers: Uint8Array
) => {
  const header = await decryptHeaderRanges(key, iv, headers)
  if (!header) {
    throw new Error("Header not found")
  }
  const [dataStart, dataSize] = header
    .split(":")
    .map((value: string) => parseInt(value))
  return [dataStart, dataStart + dataSize]
}

const decryptData = (
  key: Uint8Array,
  data: Uint8Array,
  ciphertextStart: number,
  ciphertextEnd: number
) => {
  const ciphertext = data.subarray(ciphertextStart, ciphertextEnd)
  const ivEnd = ciphertextEnd + GCM_IV_LENGTH
  const iv = data.subarray(ciphertextEnd, ivEnd)
  const authTag = data.subarray(ivEnd, ivEnd + GCM_TAG_LENGTH)
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
const decrypt = async (
  passphrase: string,
  salt: Uint8Array,
  iv: Uint8Array,
  headers: Uint8Array,
  data: Uint8Array,
  kdf: Kdf
): Promise<Uint8Array> => {
  const key = await kdf(passphrase, toHexString(salt))
  const [dataStart, dataEnd] = await decryptHeaders(key, iv, headers)
  const message = await decryptData(key, data, dataStart, dataEnd)
  return isWebEnv() ? message : Buffer.from(message)
}

export default decrypt
