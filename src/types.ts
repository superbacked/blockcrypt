import type { webcrypto } from "crypto"

export interface Block {
  salt: Uint8Array
  iv: Uint8Array
  headers: Uint8Array
  data: Uint8Array
}

export type EncryptedSecret = {
  key: Uint8Array
  ciphertext: Uint8Array
}

export type Kdf = (passphrase: string, salt: string) => Promise<Uint8Array>

export type Message = Uint8Array | string

export interface Secret {
  message: Message
  passphrase: string
}

export type WebCrypto = Crypto | webcrypto.Crypto
