const BASE64_ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="

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

export const isWebEnvironment = () => typeof window === "object"

const indicesToBase64 = (indices: number[]) =>
  indices.map((index) => BASE64_ALPHABET.charAt(index))

const bytesToBase64 = (
  firstByte: number,
  secondByte?: number,
  thirdByte?: number
) => {
  if (Number.isInteger(thirdByte)) {
    return indicesToBase64([
      firstByte >> 2,
      ((firstByte & 3) << 4) | (secondByte >> 4),
      ((secondByte & 15) << 2) | (thirdByte >> 6),
      thirdByte & 63,
    ])
  }
  if (Number.isInteger(secondByte)) {
    return indicesToBase64([
      firstByte >> 2,
      ((firstByte & 3) << 4) | (secondByte >> 4),
      (secondByte & 15) << 2,
      64,
    ])
  }
  return indicesToBase64([firstByte >> 2, (firstByte & 3) << 4, 64, 64])
}

const splitBytes = (data: Uint8Array, size: number) => {
  const length = Math.ceil(data.byteLength / size)
  return Array.from({ length }, (_, index) => {
    const begin = index * size
    return index + 1 === length
      ? data.subarray(begin)
      : data.subarray(begin, begin + size)
  })
}

export const toBase64 = (data: Uint8Array) =>
  splitBytes(data, 3)
    .map((chunk) => bytesToBase64.apply(null, chunk))
    .flat()
    .join("")

export const toUTF8String = (data: Uint8Array) => new TextDecoder().decode(data)
