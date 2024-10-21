import {
  createCipheriv,
  createDecipheriv,
  hkdfSync,
  randomBytes,
} from "node:crypto"

export type Message = Buffer | string

export interface Secret {
  message: Message
  passphrase: string
}

export type Kdf = (passphrase: string, salt: string) => Promise<Buffer>

export const getDataLength = (message: Message): number => {
  const messageLength = Buffer.from(message).byteLength
  return messageLength + 16
}

const deriveKey = (
  ikm: Buffer,
  context: string,
): Buffer => {
  const okm = hkdfSync("sha256", ikm, "", context, 32)
  return Buffer.from(okm)
}

const deriveKeys = async (
  passphrase: string,
  salt: Buffer,
  kdf: Kdf,
): Promise<[Buffer, Buffer]> => {
  const ikm = await kdf(passphrase, salt.toString("base64"))
  const headerKey = deriveKey(ikm, "header")
  const messageKey = deriveKey(ikm, "message")
  return [headerKey, messageKey]
}

const encryptPlaintext = (key: Buffer, plaintext: Buffer): Buffer => {
  const cipher = createCipheriv(
    "chacha20-poly1305",
    key,
    Buffer.alloc(12),
  )
  return Buffer.concat([
    cipher.update(plaintext),
    cipher.final(),
    // @ts-ignore
    cipher.getAuthTag(),
  ])
}

const pad = (message: Message): Buffer => {
  const plaintext = Buffer.from(message)
  const desiredSize = Math.ceil(plaintext.byteLength / 8) * 8
  return Buffer.concat([
    plaintext,
    Buffer.from([128]),
    Buffer.alloc(desiredSize - plaintext.byteLength - 1),
  ])
}

const encryptMessage = (
  key: Buffer,
  message: Message,
): Buffer => encryptPlaintext(key, pad(message))

const encryptHeader = (
  key: Buffer,
  ciphertext: Buffer,
): Buffer => {
  const header = Buffer.alloc(8)
  const view = new DataView(header.buffer)
  view.setUint32(4, ciphertext.byteLength)
  return encryptPlaintext(key, header)
}

const encryptSecret = async (
  passphrase: string,
  salt: Buffer,
  kdf: Kdf,
  message: Message,
): Promise<Buffer> => {
  const [headerKey, messageKey] = await deriveKeys(
    passphrase,
    salt,
    kdf,
  )
  const ciphertext = encryptMessage(messageKey, message)
  const header = encryptHeader(headerKey, ciphertext)
  return Buffer.concat([header, ciphertext])
}

const addNoise = (bytes: Buffer, desiredLength: number): Buffer => {
  const noise = randomBytes(desiredLength - bytes.byteLength)
  return Buffer.concat([bytes, noise])
}

class Block {
  blockSize: number
  block: Buffer
  kdf: Kdf
  salt: Buffer

  constructor(
    blockSize: number,
    kdf: Kdf,
  ) {
    if (blockSize === 0 || blockSize % 8 !== 0) {
      throw new Error("Invalid block size")
    }
    this.blockSize = blockSize
    this.block = Buffer.from([])
    this.kdf = kdf
    this.salt = randomBytes(16)
  }

  async encrypt(passphrase: string, message: Message) {
    const entry = await encryptSecret(
      passphrase,
      this.salt,
      this.kdf,
      message,
    )
    this.block = Buffer.concat([this.block, entry])
  }

  finalize(): Buffer {
    this.block = Buffer.concat([this.salt, this.block])
    if (this.block.byteLength > this.blockSize) {
      throw new Error("Block size exceeded")
    }
    return addNoise(this.block, this.blockSize)
  }
}

const isValidSecrets = (secrets: Secret[]): boolean =>
  secrets instanceof Array &&
  secrets.length > 0 &&
  secrets.every(
    (secret) =>
      Buffer.from(secret.message || "").byteLength > 0 &&
      (secret.passphrase || "").length > 0,
  )

export const encrypt = async (
  secrets: Secret[],
  kdf: Kdf,
  blockSize: number,
): Promise<Buffer> => {
  if (!isValidSecrets(secrets)) {
    throw new Error("Invalid secrets")
  }
  const block = new Block(blockSize, kdf)
  await Promise.all(
    secrets.map((secret) => block.encrypt(secret.passphrase, secret.message)),
  )
  return block.finalize()
}

const decryptCiphertext = (key: Buffer, ciphertext: Buffer): Buffer => {
  const decipher = createDecipheriv(
    "chacha20-poly1305",
    key,
    Buffer.alloc(12),
  )
  // @ts-ignore
  decipher.setAuthTag(ciphertext.subarray(-16))
  return Buffer.concat([
    decipher.update(ciphertext.subarray(0, ciphertext.byteLength - 16)),
    decipher.final(),
  ])
}

const parseHeader = (header: Buffer, start: number): [number, number] => {
  const view = new DataView(header.buffer, header.byteOffset, header.byteLength)
  const size = view.getUint32(4)
  return [start, start + size]
}

const decryptHeader = (
  key: Buffer,
  block: Buffer,
): [number, number] => {
  for (let start = 0; start < block.byteLength; start += 8) {
    try {
      const end = start + 24
      const header = decryptCiphertext(key, block.subarray(start, end))
      return parseHeader(header, end)
    } catch {}
  }
  throw new Error("Decryption failed")
}

const calculateUnpaddedSize = (padded: Buffer): number => {
  const size = padded.byteLength
  for (let i = size - 1; i >= size - 8; i--) {
    const byte = padded[i]
    if (byte === 128) {
      return i
    }
    if (byte !== 0) {
      return 0
    }
  }
  return 0
}

const unpad = (message: Buffer): Buffer => {
  const size = calculateUnpaddedSize(message)
  if (size === 0) {
    throw new Error("Invalid padding")
  }
  return message.subarray(0, size)
}

const decryptSecret = (
  headerKey: Buffer,
  messageKey: Buffer,
  block: Buffer,
): Buffer => {
  const [start, end] = decryptHeader(headerKey, block)
  const message = decryptCiphertext(messageKey, block.subarray(start, end))
  return unpad(message)
}

export const decrypt = async (
  passphrase: string,
  block: Buffer,
  kdf: Kdf,
): Promise<Buffer> => {
  const [headerKey, messageKey] = await deriveKeys(
    passphrase,
    block.subarray(0, 16),
    kdf,
  )
  return decryptSecret(headerKey, messageKey, block.subarray(16))
}
