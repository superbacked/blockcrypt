import type { webcrypto } from "crypto"
import { concat, toUint8Array } from "./util"

const loadCrypto = async () => {
  if (typeof window === "object") {
    return window.crypto
  }
  const { webcrypto } = await import("crypto")
  return webcrypto
}

let webCrypto: Crypto | webcrypto.Crypto = null

const getCrypto = async () => {
  if (!webCrypto) {
    webCrypto = await loadCrypto()
  }
  return webCrypto
}

const importSecretKey = async (key: Uint8Array, algorithm: string) =>
  (await getCrypto()).subtle.importKey("raw", key, algorithm, false, [
    "encrypt",
    "decrypt",
  ])

export const encryptCBC = async (
  key: Uint8Array,
  iv: Uint8Array,
  message: Uint8Array
) => {
  const crypto = await getCrypto()
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: "AES-CBC",
      iv,
    },
    await importSecretKey(key, "AES-CBC"),
    message
  )
  return toUint8Array(ciphertext)
}

export const encryptGCM = async (
  key: Uint8Array,
  iv: Uint8Array,
  message: Uint8Array
) => {
  const crypto = await getCrypto()
  const result = toUint8Array(
    await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv,
        tagLength: 128,
      },
      await importSecretKey(key, "AES-GCM"),
      message
    )
  )
  return {
    ciphertext: result.subarray(0, result.byteLength - 16),
    authTag: result.subarray(-16),
  }
}

export const decryptCBC = async (
  key: Uint8Array,
  iv: Uint8Array,
  ciphertext: Uint8Array
) => {
  const crypto = await getCrypto()
  const message = await crypto.subtle.decrypt(
    {
      name: "AES-CBC",
      iv,
    },
    await importSecretKey(key, "AES-CBC"),
    ciphertext
  )
  return toUint8Array(message)
}

export const decryptGCM = async (
  key: Uint8Array,
  iv: Uint8Array,
  ciphertext: Uint8Array,
  authTag: Uint8Array
) => {
  const crypto = await getCrypto()
  const message = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv,
      tagLength: 128,
    },
    await importSecretKey(key, "AES-GCM"),
    concat([ciphertext, authTag])
  )
  return toUint8Array(message)
}

export const randomBytes = async (size: number) => {
  const crypto = await getCrypto()
  // @ts-ignore
  return toUint8Array(crypto.getRandomValues(new Uint8Array(size)))
}
