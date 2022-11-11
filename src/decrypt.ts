import { decryptCBC, decryptGCM } from "./crypto"
import { Kdf } from "./types"
import { isWebEnvironment, toBase64, toUTF8String } from "./util"

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
      const header: string = await promise
      if (header) {
        return header
      }
      try {
        const str = await decryptHeader(key, iv, headers, start, end)
        if (str.match(/^[0-9]+:[0-9]+$/)) {
          return str
        }
      } catch (error) {}
      return header
    },
    Promise.resolve("")
  )
  if (!result) {
    throw new Error("Header not found")
  }
  const [dataStart, dataSize] = result
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
const decrypt = async (
  passphrase: string,
  salt: Uint8Array,
  iv: Uint8Array,
  headers: Uint8Array,
  data: Uint8Array,
  kdf: Kdf
): Promise<Uint8Array> => {
  const key = await kdf(passphrase, toBase64(salt))
  const [dataStart, dataEnd] = await decryptHeaders(key, iv, headers)
  const message = await decryptData(key, data, dataStart, dataEnd)
  return isWebEnvironment() ? message : Buffer.from(message)
}

export default decrypt
