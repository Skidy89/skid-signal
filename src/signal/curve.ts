import * as curve from "../../native";
type KeyPair = {
    private: Uint8Array
    public: Uint8Array
}
export const generateSignalPubKey = (pubKey: Buffer) =>
	pubKey.length === 33 ? pubKey : Buffer.concat([Buffer.from([0x05]), pubKey])
export const Curve = {
	generateKeyPair: (): KeyPair => {
		const { pubKey, privKey } = curve.generateKeyPair()
		return {
			private: privKey,
			public: pubKey.subarray(1)
		}
	},
	sharedKey: (privateKey: Buffer, publicKey: Buffer) => {
		const shared = curve.signMessage(generateSignalPubKey(publicKey), privateKey)
		return shared
	},
	sign: (privateKey: Buffer, buf: Buffer) => curve.signMessage(privateKey, buf),
	verify: (pubKey: Buffer, message: Buffer, signature: Buffer) => {
		try {
			curve.verifySignature(generateSignalPubKey(pubKey), message, signature)
			return true
		} catch (error) {
			return false
		}
	}
}