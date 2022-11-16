import { Block, WebCrypto } from "./types"

const importCrypto = async () => {
  if (typeof window === "object") {
    return window.crypto
  }
  const { webcrypto } = await import("crypto")
  return webcrypto
}

let crypto: WebCrypto = null

export const getCrypto = async () => {
  if (!crypto) {
    crypto = await importCrypto()
  }
  return crypto
}

export const toUint8Array = (data: string | BufferSource) => {
  if (typeof data === "string") {
    return new TextEncoder().encode(data)
  }
  if (data instanceof ArrayBuffer) {
    return new Uint8Array(data)
  }
  if (ArrayBuffer.isView(data)) {
    return new Uint8Array(data.buffer, data.byteOffset, data.byteLength)
  }
  return Uint8Array.from([])
}

export const concat = (chunks: BufferSource[]) =>
  Uint8Array.from(chunks.map((chunk) => [...toUint8Array(chunk)]).flat())

export const createBufferBlock = (block: Block): Block => ({
  salt: Buffer.from(block.salt),
  iv: Buffer.from(block.iv),
  headers: Buffer.from(block.headers),
  data: Buffer.from(block.data),
})

export const isWebEnv = () => typeof window === "object"

export const toUTF8String = (data: Uint8Array) => new TextDecoder().decode(data)

export const toHexString = (data: Uint8Array) =>
  [...data].map((byte) => byte.toString(16).padStart(2, "0")).join("")
