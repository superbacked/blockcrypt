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

export interface Block {
  salt: Buffer
  iv: Buffer
  headers: Buffer
  data: Buffer
}

export const getDataLength = (message: Message): number => {
  const messageLength = Buffer.from(message).byteLength
  return messageLength + 12 + 16
}

const deriveKey = (
  ikm: Buffer,
  context: string,
  legacyMode: boolean,
): Buffer => {
  if (legacyMode) {
    return ikm
  }
  const okm = hkdfSync("sha256", ikm, "", context, 32)
  return Buffer.from(okm)
}

const encryptHeader = (
  key: Buffer,
  iv: Buffer,
  dataStart: number,
  dataSize: number,
  legacyMode: boolean,
): Buffer => {
  const cipher = createCipheriv(
    "aes-256-cbc",
    deriveKey(key, "headers", legacyMode),
    iv,
  )
  return Buffer.concat([
    cipher.update(`${dataStart}:${dataSize}`),
    cipher.final(),
  ])
}

const encryptMessage = (
  key: Buffer,
  message: Buffer,
  legacyMode: boolean,
): Buffer => {
  const iv = randomBytes(12)
  const cipher = createCipheriv(
    "aes-256-gcm",
    deriveKey(key, "data", legacyMode),
    iv,
  )
  return Buffer.concat([
    cipher.update(message),
    cipher.final(),
    iv,
    cipher.getAuthTag(),
  ])
}

const encryptSecret = (
  key: Buffer,
  iv: Buffer,
  message: Buffer,
  data: Buffer,
  legacyMode: boolean,
): [Buffer, Buffer] => {
  const dataCiphertext = encryptMessage(key, message, legacyMode)
  const headerCiphertext = encryptHeader(
    key,
    iv,
    data.byteLength,
    message.byteLength,
    legacyMode,
  )
  return [headerCiphertext, dataCiphertext]
}

const addNoise = (bytes: Buffer, desiredLength: number): Buffer => {
  const noise = randomBytes(desiredLength - bytes.byteLength)
  return Buffer.concat([bytes, noise])
}

class Blockcrypt {
  kdf: Kdf
  headersLength: number
  dataLength?: number
  salt: Buffer
  iv: Buffer
  legacyMode: boolean
  headers: Buffer
  data: Buffer

  constructor(
    kdf: Kdf,
    headersLength?: number,
    dataLength?: number,
    salt?: Buffer,
    iv?: Buffer,
    legacyMode?: boolean,
  ) {
    if (headersLength && headersLength % 16 !== 0) {
      throw new Error("Invalid headers length")
    }
    if (dataLength && dataLength % 16 !== 0) {
      throw new Error("Invalid data length")
    }
    this.kdf = kdf
    this.headersLength = headersLength || 64
    this.dataLength = dataLength
    this.salt = salt || randomBytes(16)
    this.iv = iv || randomBytes(16)
    this.legacyMode = legacyMode === true
    this.headers = Buffer.from([])
    this.data = Buffer.from([])
  }

  async encrypt(passphrase: string, message: Message) {
    const key = await this.kdf(passphrase, this.salt.toString("base64"))
    const [header, data] = encryptSecret(
      key,
      this.iv,
      Buffer.from(message),
      this.data,
      this.legacyMode,
    )
    if (!this.dataLength && this.data.byteLength == 0) {
      this.dataLength = Math.ceil((data.byteLength * 2) / 64) * 64
    }
    this.headers = Buffer.concat([this.headers, header])
    this.data = Buffer.concat([this.data, data])
  }

  finalize(): Block {
    if (!this.dataLength) {
      throw new Error("Unknown data length")
    }
    if (this.data.byteLength > this.dataLength) {
      throw new Error("Data too long for data length")
    }
    if (this.headers.byteLength > this.headersLength) {
      throw new Error("Headers too long for headers length")
    }
    const headers = addNoise(this.headers, this.headersLength)
    const data = addNoise(this.data, this.dataLength)
    return {
      salt: this.salt,
      iv: this.iv,
      headers,
      data,
    }
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
  headersLength?: number,
  dataLength?: number,
  salt?: Buffer,
  iv?: Buffer,
  legacyMode?: boolean,
): Promise<Block> => {
  if (!isValidSecrets(secrets)) {
    throw new Error("Invalid secrets")
  }
  const block = new Blockcrypt(
    kdf,
    headersLength,
    dataLength,
    salt,
    iv,
    legacyMode,
  )
  await Promise.all(
    secrets.map((secret) => block.encrypt(secret.passphrase, secret.message)),
  )
  return block.finalize()
}

const decryptHeader = (
  key: Buffer,
  iv: Buffer,
  headers: Buffer,
  start: number,
  end: number,
): [number, number] | null => {
  try {
    const decipher = createDecipheriv("aes-256-cbc", key, iv)
    const plaintext = Buffer.concat([
      decipher.update(headers.subarray(start, end)),
      decipher.final(),
    ])
    const header = plaintext.toString()
    if (header.match(/^[0-9]+:[0-9]+$/)) {
      const offsets = header.split(":")
      const dataStart = parseInt(offsets[0])
      const dataSize = parseInt(offsets[1])
      return [dataStart, dataStart + dataSize]
    }
  } catch {
    return null
  }
}

const decryptHeaders = (
  key: Buffer,
  iv: Buffer,
  headers: Buffer,
): [number, number] => {
  for (let start = 0; start < headers.byteLength; start++) {
    for (let end = headers.byteLength; end > start; end--) {
      const dataOffsets = decryptHeader(key, iv, headers, start, end)
      if (dataOffsets) {
        return dataOffsets
      }
    }
  }
  throw new Error("Header not found")
}

const decryptMessage = (
  key: Buffer,
  data: Buffer,
  start: number,
  end: number,
): Buffer => {
  const ciphertext = data.subarray(start, end)
  const ivEnd = end + 12
  const iv = data.subarray(end, ivEnd)
  const authTag = data.subarray(ivEnd, ivEnd + 16)
  const decipher = createDecipheriv("aes-256-gcm", key, iv)
  decipher.setAuthTag(authTag)
  return Buffer.concat([decipher.update(ciphertext), decipher.final()])
}

export const decrypt = async (
  passphrase: string,
  salt: Buffer,
  iv: Buffer,
  headers: Buffer,
  data: Buffer,
  kdf: Kdf,
  legacyMode?: boolean,
): Promise<Buffer> => {
  const key = await kdf(passphrase, salt.toString("base64"))
  const headersKey = deriveKey(key, "headers", legacyMode)
  const dataKey = deriveKey(key, "data", legacyMode)
  const [dataStart, dataEnd] = decryptHeaders(headersKey, iv, headers)
  return decryptMessage(dataKey, data, dataStart, dataEnd)
}
