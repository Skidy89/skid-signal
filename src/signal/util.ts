export type Bytes = Buffer
export type MaybePromise<T> = T | Promise<T>

export const KEY_TYPE = 0x05

export const toBuf = (b: Buffer | Uint8Array) => {
  if (Buffer.isBuffer(b)) return b
  return Buffer.from(b)
}


export function pub33(key: Bytes): Buffer {
  const b = key
  if (b.length === 33 && b[0] === KEY_TYPE) return b
  if (b.length === 32) return Buffer.concat([Buffer.from([KEY_TYPE]), b])
  throw new Error('Invalid public key')
}


const tails = new Map<string, Promise<void>>()
export function queueJob<T>(key: string, job: () => Promise<T>): Promise<T> {
  const prev = tails.get(key) ?? Promise.resolve()
  const run = prev.then(job)
  const tail = run.then(() => undefined, () => undefined)
  tails.set(key, tail)
  void tail.then(() => {
    if (tails.get(key) === tail) tails.delete(key)
  })
  return run
}



export function recordBytes(data: unknown): Buffer | null {
  if (data instanceof Uint8Array) {
    const b = toBuf(data)
    return b.length ? b : null
  }
  return null
}