import { unpack } from 'msgpackr'
import { Bytes } from './util'

interface LegacyState {
  senderKeyId: number
  senderChainKey: { iteration: number; seed: Uint8Array }
  senderSigningKey: { public: Uint8Array; private?: Uint8Array | null }
  senderMessageKeys?: Array<{ iteration: number; seed: Uint8Array }>
}

function varint(n: number): Buffer {
  const out: number[] = []
  let v = n
  while (v > 0x7f) {
    out.push((v % 128) | 0x80)
    v = Math.floor(v / 128)
  }
  out.push(v)
  return Buffer.from(out)
}

const tag = (field: number, wire: number) => varint(field * 8 + wire)
const fVarint = (field: number, n: number) => Buffer.concat([tag(field, 0), varint(n)])
const fBytes = (field: number, b: Uint8Array) =>
  Buffer.concat([tag(field, 2), varint(b.length), b])

const isBytes = (x: unknown): x is Uint8Array => x instanceof Uint8Array

function encodeState(s: LegacyState): Buffer {
  const chain = Buffer.concat([
    fVarint(1, s.senderChainKey.iteration),
    fBytes(2, s.senderChainKey.seed),
  ])
  const signing = Buffer.concat([
    fBytes(1, s.senderSigningKey.public),
    ...(isBytes(s.senderSigningKey.private) ? [fBytes(2, s.senderSigningKey.private)] : []),
  ])
  const skipped = (s.senderMessageKeys ?? []).map(k =>
    fBytes(4, Buffer.concat([fVarint(1, k.iteration), fBytes(2, k.seed)])),
  )
  return Buffer.concat([
    fVarint(1, s.senderKeyId),
    fBytes(2, chain),
    fBytes(3, signing),
    ...skipped,
  ])
}

const validState = (s: LegacyState): boolean =>
  !!s &&
  Number.isInteger(s.senderKeyId) &&
  isBytes(s.senderChainKey?.seed) &&
  Number.isInteger(s.senderChainKey?.iteration) &&
  isBytes(s.senderSigningKey?.public)

/** msgpack (array 0x90-0x9f / 0xdc)
 *  protobuf (0x0a)
 */
export function isLegacySenderKeyRecord(b: Buffer): boolean {
  return b[0] !== 0x0a && ((b[0] & 0xf0) === 0x90 || b[0] === 0xdc)
}

// returns null for empty or legacy format (libsignal-node), which is treated as "no session".
export function migrateLegacySenderKeyRecord(data: Bytes): Buffer | null {
  let states: LegacyState[]
  try {
    states = unpack(data) as LegacyState[]
  } catch {
    return null
  }
  if (!Array.isArray(states)) return null
  const parts = states.filter(validState).map(s => fBytes(1, encodeState(s)))
  return parts.length ? Buffer.concat(parts) : null
}