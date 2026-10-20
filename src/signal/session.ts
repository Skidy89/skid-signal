import * as native from '../../native'
import { ProtocolAddress } from './address'
import { PreKeyError, SessionError, UntrustedIdentityKeyError } from './errors'
import { SessionRecord } from './records'
import { Bytes, MaybePromise, pub33, queueJob } from './util'

export interface KeyPairLike {
  pubKey: Bytes
  privKey: Bytes
}

export interface SignalStorage {
  loadSession(id: string): MaybePromise<SessionRecord | null | undefined>
  storeSession(id: string, record: SessionRecord): MaybePromise<void>
  isTrustedIdentity?(identifier: string, identityKey: Buffer): MaybePromise<boolean>
  loadPreKey(id: number): MaybePromise<KeyPairLike | null | undefined>
  removePreKey(id: number): MaybePromise<void>
  loadSignedPreKey(id: number): MaybePromise<KeyPairLike | null | undefined>
  getOurRegistrationId(): MaybePromise<number>
  getOurIdentity(): MaybePromise<KeyPairLike>
}

export interface PreKeyBundle {
  registrationId: number
  identityKey: Bytes
  signedPreKey: { keyId: number; publicKey: Bytes; signature: Bytes }
  preKey?: { keyId: number; publicKey: Bytes }
}

const keyPair = (k: KeyPairLike) => ({ pubKey: pub33(k.pubKey), privKey: k.privKey })

async function assertTrusted(storage: SignalStorage, name: string, identityKey: Buffer) {
  if (storage.isTrustedIdentity && !(await storage.isTrustedIdentity(name, identityKey))) {
    throw new UntrustedIdentityKeyError(name, identityKey)
  }
}

export class SessionBuilder {
  constructor(
    private readonly storage: SignalStorage,
    private readonly addr: ProtocolAddress,
  ) {}


  initOutgoing(device: PreKeyBundle): Promise<void> {
    const id = this.addr.toString()
    return queueJob(id, async () => {
      const identityKey = pub33(device.identityKey)
      await assertTrusted(this.storage, this.addr.id, identityKey)
      const existing = await this.storage.loadSession(id)
      const ours = await this.storage.getOurIdentity()
      const record = native.sessionProcessPrekeyBundle(existing?.raw ?? null, keyPair(ours), {
        registrationId: device.registrationId,
        identityKey,
        signedPreKeyId: device.signedPreKey.keyId,
        signedPreKey: pub33(device.signedPreKey.publicKey),
        signedPreKeySignature: device.signedPreKey.signature,
        preKeyId: device.preKey?.keyId,
        preKey: device.preKey ? pub33(device.preKey.publicKey) : undefined,
      })
      await this.storage.storeSession(id, new SessionRecord(record))
    })
  }
}

export class SessionCipher {
  private readonly addr: ProtocolAddress
  private readonly id: string

  constructor(
    private readonly storage: SignalStorage,
    addr: ProtocolAddress | string,
  ) {
    this.addr = typeof addr === 'string' ? ProtocolAddress.from(addr) : addr
    this.id = this.addr.toString()
  }

  async hasOpenSession(): Promise<boolean> {
    const rec = await this.storage.loadSession(this.id)
    return !!rec && rec.haveOpenSession()
  }

 
  encrypt(data: Bytes): Promise<{ type: number; body: string; registrationId: number }> {
    return queueJob(this.id, async () => {
      const rec = await this.storage.loadSession(this.id)
      if (!rec?.raw) throw new SessionError('No sessions')
      const ours = await this.storage.getOurIdentity()
      const regId = await this.storage.getOurRegistrationId()
      const out = native.sessionEncrypt(rec.raw, pub33(ours.pubKey), regId, data)
      await this.storage.storeSession(this.id, new SessionRecord(out.newRecord))
      return { type: out.msgType, body: out.body.toString('binary'), registrationId: out.registrationId }
    })
  }

  decryptWhisperMessage(data: Bytes): Promise<Buffer> {
    return queueJob(this.id, async () => {
      const rec = await this.storage.loadSession(this.id)
      if (!rec?.raw) throw new SessionError(`No session record for ${this.id}`)
      const ours = await this.storage.getOurIdentity()
      const out = native.sessionDecryptWhisper(rec.raw, pub33(ours.pubKey), data)
      await this.storage.storeSession(this.id, new SessionRecord(out.newRecord))
      return out.plaintext
    })
  }

  decryptPreKeyWhisperMessage(data: Bytes): Promise<Buffer> {
    return queueJob(this.id, async () => {
      const msg = data
      const parsed = native.parsePrekeyMessage(msg)
      await assertTrusted(this.storage, this.addr.id, parsed.identityKey)

      const existing = await this.storage.loadSession(this.id)
      const ours = await this.storage.getOurIdentity()
      const signed = await this.storage.loadSignedPreKey(parsed.signedPreKeyId)
      if (!signed) throw new PreKeyError('Missing signed prekey')
      const pre = parsed.preKeyId != null ? await this.storage.loadPreKey(parsed.preKeyId) : null

      const out = native.sessionDecryptPrekey(
        existing?.raw ?? null,
        keyPair(ours),
        keyPair(signed),
        pre ? keyPair(pre) : null,
        msg,
      )
      await this.storage.storeSession(this.id, new SessionRecord(out.newRecord))
      if (out.usedPreKeyId != null) await this.storage.removePreKey(out.usedPreKeyId)
      return out.plaintext
    })
  }
}