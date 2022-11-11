export interface Block {
  salt: Uint8Array
  iv: Uint8Array
  headers: Uint8Array
  data: Uint8Array
}

export interface BufferBlock {
  salt: Buffer
  iv: Buffer
  headers: Buffer
  data: Buffer
}

export type Kdf = (passphrase: string, salt: string) => Promise<Uint8Array>

export type Message = Uint8Array | string

export interface Secret {
  message: Message
  passphrase: string
}
