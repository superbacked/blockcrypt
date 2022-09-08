import { createCipheriv, createDecipheriv, randomBytes } from "crypto"
import bs58 from "bs58"
import wordlist from "./wordlist.js"

const algorithm = "aes-256-cbc"

export interface Secret {
  message: string
  passphrase: string
}

export type Kdf = (passphrase: string, salt?: string) => Promise<string>

export interface Block {
  salt: string
  iv: string
  ciphertext: string
  needles: string[]
}

/**
 * Get index of needle
 * @param needle needle
 * @returns index
 */
export const getNeedleIndex = (needle: string) => {
  for (const [index, word] of wordlist.entries()) {
    if (word === needle) {
      return index
    }
  }
  return null
}

/**
 * Encrypt secrets using AES-256-CBC
 * @param secrets secrets
 * @param kdf key derivation function
 * @param blockSize block size (defaults to 1024)
 * @param salt optional, salt used for deterministic unit tests
 * @param iv optional, initialization vector used for deterministic unit tests
 * @returns encrypted “block”
 */
export const encrypt = async (
  secrets: Secret[],
  kdf: Kdf,
  blockSize = 1024,
  salt?: Buffer,
  iv?: Buffer
): Promise<Block> => {
  if (salt === undefined) {
    salt = randomBytes(16)
  }
  if (iv === undefined) {
    iv = randomBytes(16)
  }
  let ciphertext = ""
  let needles: string[] = []
  for (const secret of secrets) {
    const key = await kdf(secret.passphrase, bs58.encode(salt))
    const cipher = createCipheriv(algorithm, Buffer.from(key, "hex"), iv)
    const encrypted = cipher.update(secret.message)
    const buffer = Buffer.concat([encrypted, cipher.final()])
    needles.push(wordlist[ciphertext.length])
    ciphertext += bs58.encode(buffer)
  }
  const length = ciphertext.length
  if (length > blockSize) {
    throw new Error("Secrets too large for block size")
  }
  ciphertext += bs58.encode(randomBytes(blockSize - length))
  return {
    salt: bs58.encode(salt),
    iv: bs58.encode(iv),
    ciphertext: ciphertext.substring(0, blockSize),
    needles: needles,
  }
}

/**
 * Decrypt secret
 * @param passphrase passphrase
 * @param salt salt
 * @param iv initialization vector
 * @param ciphertext ciphertext
 * @param kdf key derivation function
 * @param needle optional, needle used to significantly speed up parsing
 * @returns secret
 */
export const decrypt = async (
  passphrase: string,
  salt: string,
  iv: string,
  ciphertext: string,
  kdf: Kdf,
  needle?: string
): Promise<string> => {
  const key = await kdf(passphrase, salt)
  let start = 0
  let index: number | null
  if (needle && (index = getNeedleIndex(needle))) {
    start = index
  }
  let message: string | null = null
  while (start < ciphertext.length) {
    for (let end = ciphertext.length; end > start; end--) {
      try {
        const decipher = createDecipheriv(
          algorithm,
          Buffer.from(key, "hex"),
          bs58.decode(iv)
        )
        const decrypted = decipher.update(
          bs58.decode(ciphertext.substring(start, end))
        )
        const buffer = Buffer.concat([decrypted, decipher.final()])
        const string = buffer.toString()
        if (!string.match(/�/)) {
          message = string
        }
        if (message) {
          break
        }
      } catch (error) {}
    }
    if (message) {
      break
    }
    start++
  }
  if (!message) {
    throw new Error("Secret not found")
  }
  return message
}
