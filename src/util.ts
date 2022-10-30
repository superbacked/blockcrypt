const BASE64_ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="

export const toUint8Array = (data: Uint8Array | string) => {
  if (typeof data === "string") {
    return new TextEncoder().encode(data)
  }
  return Uint8Array.from(data)
}

export const concat = (chunks: Uint8Array[]) =>
  Uint8Array.from(chunks.map((chunk) => [...toUint8Array(chunk)]).flat())

export const toUTF8String = (data: Uint8Array) => new TextDecoder().decode(data)

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
