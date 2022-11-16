import { CIPHER_CBC, CIPHER_GCM, GCM_TAG_LENGTH } from "./constants"
import { WebCrypto } from "./types"
import { concat, getCrypto, toUint8Array } from "./util"

const getCipherParams = (name: string, iv: Uint8Array) => ({
  name,
  iv,
  tagLength: name === CIPHER_GCM ? GCM_TAG_LENGTH * 8 : undefined,
})

const importSecretKey = async (
  crypto: WebCrypto,
  key: Uint8Array,
  cipher: string
) => crypto.subtle.importKey("raw", key, cipher, false, ["encrypt", "decrypt"])

const encrypt = async (
  cipher: string,
  key: Uint8Array,
  iv: Uint8Array,
  message: Uint8Array
) => {
  const crypto = await getCrypto()
  const ciphertext = await crypto.subtle.encrypt(
    getCipherParams(cipher, iv),
    await importSecretKey(crypto, key, cipher),
    message
  )
  return toUint8Array(ciphertext)
}

export const encryptCBC = async (
  key: Uint8Array,
  iv: Uint8Array,
  message: Uint8Array
) => encrypt(CIPHER_CBC, key, iv, message)

export const encryptGCM = async (
  key: Uint8Array,
  iv: Uint8Array,
  message: Uint8Array
) => {
  const result = await encrypt(CIPHER_GCM, key, iv, message)
  return {
    ciphertext: result.subarray(0, result.byteLength - 16),
    authTag: result.subarray(-16),
  }
}

const decrypt = async (
  cipher: string,
  key: Uint8Array,
  iv: Uint8Array,
  ciphertext: Uint8Array
) => {
  const crypto = await getCrypto()
  const message = await crypto.subtle.decrypt(
    getCipherParams(cipher, iv),
    await importSecretKey(crypto, key, cipher),
    ciphertext
  )
  return toUint8Array(message)
}

export const decryptCBC = async (
  key: Uint8Array,
  iv: Uint8Array,
  ciphertext: Uint8Array
) => decrypt(CIPHER_CBC, key, iv, ciphertext)

export const decryptGCM = async (
  key: Uint8Array,
  iv: Uint8Array,
  ciphertext: Uint8Array,
  authTag: Uint8Array
) => decrypt(CIPHER_GCM, key, iv, concat([ciphertext, authTag]))

export const randomBytes = async (size: number) => {
  const crypto = await getCrypto()
  // @ts-ignore
  return toUint8Array(crypto.getRandomValues(new Uint8Array(size)))
}
