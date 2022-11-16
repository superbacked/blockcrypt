import { Block, Kdf, Message, Secret } from "./types"
import { toUint8Array } from "./util"
import decrypt from "./decrypt"
import encrypt from "./encrypt"

export type { Block, Kdf, Message, Secret }

/**
 * Get data length of message
 * @param message message
 * @returns data length in bytes
 */
const getDataLength = (message: Message) =>
  toUint8Array(message).byteLength + 12 + 16

export { decrypt, encrypt, getDataLength }
