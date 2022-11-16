import {
  CBC_IV_LENGTH,
  DEFAULT_SALT_LENGTH,
  GCM_IV_LENGTH,
  GCM_TAG_LENGTH,
} from "./constants"
import { encryptCBC, encryptGCM, randomBytes } from "./crypto"
import { Block, EncryptedSecret, Kdf, Secret } from "./types"
import {
  concat,
  createBufferBlock,
  isWebEnv,
  toHexString,
  toUint8Array,
} from "./util"

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
  return concat([ciphertext, iv, authTag])
}

const encryptHeader = (
  key: Uint8Array,
  iv: Uint8Array,
  byteOffset: number,
  byteLength: number
) => encryptCBC(key, iv, toUint8Array(`${byteOffset}:${byteLength}`))

const encryptHeaders = async (
  encryptedSecrets: EncryptedSecret[],
  iv: Uint8Array
) => {
  const initialState = { byteOffset: 0, headers: Uint8Array.from([]) }
  const { headers } = await encryptedSecrets.reduce(
    async (promise, { key, ciphertext }) => {
      const { byteOffset, headers } = await promise
      const header = await encryptHeader(
        key,
        iv,
        byteOffset,
        ciphertext.byteLength - (GCM_IV_LENGTH + GCM_TAG_LENGTH)
      )
      return {
        byteOffset: byteOffset + ciphertext.byteLength,
        headers: concat([headers, header]),
      }
    },
    Promise.resolve(initialState)
  )
  return headers
}

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

const calculateDataPadding = (
  ciphertexts: Uint8Array[],
  dataLength?: number
) => {
  if (!dataLength) {
    return Math.ceil((ciphertexts[0].byteLength * 2) / 64) * 64
  }
  return dataLength
}

const padData = async (
  encryptedSecrets: EncryptedSecret[],
  dataLength?: number
) => {
  const ciphertexts = encryptedSecrets.map(({ ciphertext }) => ciphertext)
  const data = concat(ciphertexts)
  const padding = await padBytes(
    data,
    calculateDataPadding(ciphertexts, dataLength),
    "Data too long for data length"
  )
  return concat([data, padding])
}

const padHeaders = async (headers: Uint8Array, headersLength: number) => {
  const padding = await padBytes(
    headers,
    headersLength,
    "Headers too long for headers length"
  )
  return concat([headers, padding])
}

const encryptSecret = async (
  secret: Secret,
  kdf: Kdf,
  salt: string
): Promise<EncryptedSecret> => {
  const key = await kdf(secret.passphrase, salt)
  return { key, ciphertext: await encryptData(key, secret) }
}

const encryptSecrets = async (
  secrets: Secret[],
  kdf: Kdf,
  saltBytes: Uint8Array,
  iv: Uint8Array,
  headersLength: number,
  dataLength?: number
) => {
  const salt = toHexString(saltBytes)
  const encryptedSecrets = await Promise.all(
    secrets.map((secret) => encryptSecret(secret, kdf, salt))
  )
  const data = await padData(encryptedSecrets, dataLength)
  const headers = await padHeaders(
    await encryptHeaders(encryptedSecrets, iv),
    headersLength
  )
  return { salt: saltBytes, iv, headers, data }
}

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
  const block = await encryptSecrets(
    secrets,
    kdf,
    salt || (await randomBytes(DEFAULT_SALT_LENGTH)),
    iv || (await randomBytes(CBC_IV_LENGTH)),
    headersLength,
    dataLength
  )
  return isWebEnv() ? block : createBufferBlock(block)
}

export default encrypt
