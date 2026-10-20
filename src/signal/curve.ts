import * as native from "../../native";
import { Bytes } from "./util";

export interface KeyPair {
  pubKey: Buffer;
  privKey: Buffer;
}

const split = (b: Buffer): KeyPair => ({
  privKey: b.subarray(0, 32),
  pubKey: b.subarray(32),
});
export const generateKeyPairs = (count: number): KeyPair[] => {
  const pairs = native.generateKeyPairs(count);
  const result: KeyPair[] = [];
  for (let i = 0; i < count; i++) {
    const privKey = pairs[i].privKey;
    const pubKey = pairs[i].pubKey;
    result.push({ privKey, pubKey });
  }
  return result;
};

export const generateKeyPair = (): KeyPair =>
  split(native.x25519GenerateKeyPair());
export const createKeyPair = (privKey: Bytes): KeyPair =>
  split(native.x25519CreateKeyPair(privKey));
export const getPublicFromPrivateKey = (privKey: Bytes): Buffer =>
  native.x25519PublicFromPrivate(privKey);
export const calculateAgreement = (pubKey: Bytes, privKey: Bytes): Buffer =>
  native.x25519Agree(pubKey, privKey);

export const calculateSignature = (privKey: Bytes, message: Bytes): Buffer =>
  native.signMessage(privKey, message);

export function verifySignature(
  pubKey: Bytes,
  message: Bytes,
  signature: Bytes,
): true {
  if (signature.length !== 64) throw new Error("Invalid signature length");
  if (!native.verifySignature(signature, pubKey, message))
    throw new Error("Invalid signature");
  return true;
}
