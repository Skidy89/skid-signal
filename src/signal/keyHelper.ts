import { randomBytes } from 'node:crypto'
import { generateKeyPair, KeyPair } from './curve'
import { signMessage } from '../../native'

export const generateIdentityKeyPair = () => generateKeyPair()

export const generateRegistrationId = (): number => randomBytes(2).readUInt16BE(0) & 0x3fff

export interface SignedPreKey {
  keyId: number
  keyPair: KeyPair
  signature: Buffer
}


export function generateSignedPreKey(identityKeyPair: KeyPair, signedKeyId: number): SignedPreKey {
  const keyPair = generateKeyPair()
  const signature = signMessage(identityKeyPair.privKey, keyPair.pubKey)
  return { keyId: signedKeyId, keyPair, signature }
}

export function generatePreKey(keyId: number): { keyId: number; keyPair: typeof generateKeyPair extends () => infer K ? K : never } {
  return { keyId, keyPair: generateKeyPair() }
}