const {
  ProtocolAddress, SessionBuilder, SessionCipher, keyhelper, curve,
  SenderKeyName, SenderKeyRecord, SenderKeyDistributionMessage,
  GroupSessionBuilder, GroupCipher, SessionRecord,
} = require('../dist')
const lib = require("../libsignal")
function makeStore(identity, registrationId, signed, preKeys = new Map()) {
  const sessions = new Map()
  return {
    loadSession: async (id) => sessions.get(id),
    storeSession: async (id, rec) => { sessions.set(id, rec) },
    isTrustedIdentity: async () => true,
    loadPreKey: async (id) => preKeys.get(Number(id)),
    removePreKey: async (id) => { preKeys.delete(Number(id)) },
    loadSignedPreKey: async () => signed.keyPair, 
    getOurRegistrationId: async () => registrationId,
    getOurIdentity: async () => identity,
  }
}

function makeLibStore(identity, registrationId, signed, preKeys = new Map()) {
  const sessions = new Map()
  return {
    loadSession: async (id) => sessions.get(id),
    storeSession: async (id, rec) => { sessions.set(id, rec) },
    isTrustedIdentity: () => true,
    loadPreKey: async (id) => preKeys.get(Number(id)),
    removePreKey: async (id) => { preKeys.delete(Number(id)) },
    loadSignedPreKey: async () => signed.keyPair,
    getOurRegistrationId: () => registrationId,
    getOurIdentity: () => identity,
  }
}

function makeBundle(identity, registrationId, signed, preKey) {
  return {
    registrationId,
    identityKey: identity.pubKey,
    signedPreKey: {
      keyId: signed.keyId,
      publicKey: signed.keyPair.pubKey,
      signature: signed.signature,
    },
    preKey: preKey && { keyId: preKey.keyId, publicKey: preKey.keyPair.pubKey },
  }
}

test('curve', () => {
  const a = curve.generateKeyPair(), b = curve.generateKeyPair()
  expect(curve.calculateAgreement(b.pubKey, a.privKey)).toEqual(curve.calculateAgreement(a.pubKey, b.privKey))
  const sig = curve.calculateSignature(a.privKey, Buffer.from('msg'))
  expect(sig).toBeInstanceOf(Buffer)
  expect(a.pubKey).toBeInstanceOf(Buffer)
  expect(a.pubKey.length).toBe(33)
  expect(sig.length).toBe(64)
  expect(curve.verifySignature(a.pubKey, Buffer.from('msg'), sig)).toBe(true)
  expect(() => curve.verifySignature(b.pubKey, Buffer.from('msg'), sig)).toThrow()
})

test('X3DH + double ratchet', async () => {
  const aId = keyhelper.generateIdentityKeyPair()
  const bId = keyhelper.generateIdentityKeyPair()
  const bSigned = keyhelper.generateSignedPreKey(bId, 1)
  const bPre = keyhelper.generatePreKey(7)
  const bobPreKeys = new Map([[7, bPre.keyPair]])
  const alice = makeStore(aId, 111, null)
  const bob = makeStore(bId, 222, bSigned, bobPreKeys)
  const aAddr = new ProtocolAddress('alice', 1)
  const bAddr = new ProtocolAddress('bob', 1)

  await new SessionBuilder(alice, bAddr).initOutgoing({
    registrationId: 222,
    identityKey: bId.pubKey,
    signedPreKey: { keyId: 1, publicKey: bSigned.keyPair.pubKey, signature: bSigned.signature },
    preKey: { keyId: 7, publicKey: bPre.keyPair.pubKey },
  })

  const a = new SessionCipher(alice, bAddr)
  const b = new SessionCipher(bob, aAddr)

  const m1 = await a.encrypt(Buffer.from('hola'))
  expect(m1.type).toBe(3)
  const p1 = await b.decryptPreKeyWhisperMessage(Buffer.from(m1.body, 'binary'))
  expect(p1.toString()).toBe('hola')
  expect(bobPreKeys.has(7)).toBe(false)

  const m2 = await b.encrypt(Buffer.from('qué tal'))
  expect(m2.type).toBe(1)
  const p2 = await a.decryptWhisperMessage(Buffer.from(m2.body, 'binary'))
  expect(p2.toString()).toBe('qué tal')
})

test('sender keys', async () => {
  const mk = () => {
    const m = new Map()
    return {
      loadSenderKey: async (n) => m.get(String(n)) ?? new SenderKeyRecord(),
      storeSenderKey: async (n, r) => { m.set(String(n), r) },
    }
  }
  const name = new SenderKeyName('grp@g.us', new ProtocolAddress('alice', 1))
  const a = mk(), b = mk()
  const skdm = await new GroupSessionBuilder(a).create(name)
  await new GroupSessionBuilder(b).process(
    name,
    new SenderKeyDistributionMessage(null, null, null, null, skdm.serialize()),
  )
  const ct = await new GroupCipher(a, name).encrypt(Buffer.from('hi'))
  expect((await new GroupCipher(b, name).decrypt(ct)).toString()).toBe('hi')
})

test('compat con libsignal-node: DH', () => {
  const mine = curve.generateKeyPair()
  const theirs = lib.curve.generateKeyPair()
  const msg = Buffer.from('mensaje')

  expect(Buffer.from(curve.calculateAgreement(theirs.pubKey, mine.privKey))).toEqual(
    Buffer.from(lib.curve.calculateAgreement(mine.pubKey, theirs.privKey)),
  )


  const sigMine = curve.calculateSignature(mine.privKey, msg)
  expect(() => lib.curve.verifySignature(mine.pubKey, msg, sigMine)).not.toThrow()


  const sigTheirs = lib.curve.calculateSignature(theirs.privKey, msg)
  expect(curve.verifySignature(theirs.pubKey, msg, sigTheirs)).toBe(true)


  const bad = Buffer.from(sigMine)
  bad[0] ^= 1
  expect(() => curve.verifySignature(mine.pubKey, msg, bad)).toThrow()
})

test.each(['skid-signal inicia', 'libsignal inicia'])(
  'compatibilidad de sesiones Signal en ambos sentidos: %s', async (initiator) => {
    const aId = keyhelper.generateIdentityKeyPair()
    const bId = lib.keyhelper.generateIdentityKeyPair()
    const bSigned = lib.keyhelper.generateSignedPreKey(bId, 12)
    const bPre = lib.keyhelper.generatePreKey(34)
    const aSigned = keyhelper.generateSignedPreKey(aId, 56)
    const aPre = keyhelper.generatePreKey(78)
    const aPreKeys = new Map([[aPre.keyId, aPre.keyPair]])
    const bPreKeys = new Map([[bPre.keyId, bPre.keyPair]])
    const aStore = makeStore(aId, 101, aSigned, aPreKeys)
    const bStore = makeLibStore(bId, 202, bSigned, bPreKeys)
    const aBundle = makeBundle(aId, 101, aSigned, aPre)
    const bBundle = makeBundle(bId, 202, bSigned, bPre)
    const aCipher = new SessionCipher(aStore, new ProtocolAddress('bob-cross', 1))
    const bCipher = new lib.SessionCipher(bStore, new lib.ProtocolAddress('alice-cross', 1))

    if (initiator === 'skid-signal inicia') {
      await new SessionBuilder(aStore, new ProtocolAddress('bob-cross', 1)).initOutgoing(bBundle)
      const first = await aCipher.encrypt(Buffer.from('skid-signal -> libsignal'))
      expect(first.type).toBe(3)
      expect(await bCipher.decryptPreKeyWhisperMessage(Buffer.from(first.body, 'binary')))
        .toEqual(Buffer.from('skid-signal -> libsignal'))
    } else {
      await new lib.SessionBuilder(bStore, new lib.ProtocolAddress('alice-cross', 1)).initOutgoing(aBundle)
      const first = await bCipher.encrypt(Buffer.from('libsignal -> skid-signal'))
      expect(first.type).toBe(3)
      expect(await aCipher.decryptPreKeyWhisperMessage(Buffer.from(first.body, 'binary')))
        .toEqual(Buffer.from('libsignal -> skid-signal'))
    }

    // The initiator's pending prekey flag clears after it receives a reply.
    const confirmation = initiator === 'skid-signal inicia'
      ? await bCipher.encrypt(Buffer.from('confirmacion'))
      : await aCipher.encrypt(Buffer.from('confirmacion'))
    const confirmationReceiver = initiator === 'skid-signal inicia' ? aCipher : bCipher
    expect(confirmation.type).toBe(1)
    const confirmationPlaintext = await confirmationReceiver.decryptWhisperMessage(
      Buffer.from(confirmation.body, 'binary'),
    )
    expect(confirmationPlaintext)
      .toEqual(Buffer.from('confirmacion'))
    const aReply = await aCipher.encrypt(Buffer.from('respuesta de Alice'))
    expect(aReply.type).toBe(1)
    expect(await bCipher.decryptWhisperMessage(Buffer.from(aReply.body, 'binary')))
      .toEqual(Buffer.from('respuesta de Alice'))
    const bReply = await bCipher.encrypt(Buffer.from('respuesta de Bob'))
    expect(bReply.type).toBe(1)
    expect(await aCipher.decryptWhisperMessage(Buffer.from(bReply.body, 'binary')))
      .toEqual(Buffer.from('respuesta de Bob'))
    if (initiator === 'skid-signal inicia') expect(bPreKeys.has(bPre.keyId)).toBe(false)
    else expect(aPreKeys.has(aPre.keyId)).toBe(false)
    expect(await aCipher.hasOpenSession()).toBe(true)
    expect(await bCipher.hasOpenSession()).toBe(true)
  },
)

test('mensajes fuera de orden se descifran una sola vez', async () => {
  const aId = keyhelper.generateIdentityKeyPair()
  const bId = keyhelper.generateIdentityKeyPair()
  const bSigned = keyhelper.generateSignedPreKey(bId, 2)
  const bPre = keyhelper.generatePreKey(3)
  const bPreKeys = new Map([[3, bPre.keyPair]])
  const alice = makeStore(aId, 10, null)
  const bob = makeStore(bId, 20, bSigned, bPreKeys)
  const bAddr = new ProtocolAddress('bob-out-of-order', 1)
  const aAddr = new ProtocolAddress('alice-out-of-order', 1)
  await new SessionBuilder(alice, bAddr).initOutgoing(makeBundle(bId, 20, bSigned, bPre))
  const a = new SessionCipher(alice, bAddr)
  const b = new SessionCipher(bob, aAddr)
  const initial = await a.encrypt(Buffer.from('inicio'))
  await b.decryptPreKeyWhisperMessage(Buffer.from(initial.body, 'binary'))
  const confirmation = await b.encrypt(Buffer.from('confirmacion'))
  await a.decryptWhisperMessage(Buffer.from(confirmation.body, 'binary'))
  const messages = await Promise.all(['cero', 'uno', 'dos'].map((s) => a.encrypt(Buffer.from(s))))
  expect((await b.decryptWhisperMessage(Buffer.from(messages[2].body, 'binary'))).toString()).toBe('dos')
  expect((await b.decryptWhisperMessage(Buffer.from(messages[0].body, 'binary'))).toString()).toBe('cero')
  expect((await b.decryptWhisperMessage(Buffer.from(messages[1].body, 'binary'))).toString()).toBe('uno')
  await expect(b.decryptWhisperMessage(Buffer.from(messages[1].body, 'binary'))).rejects.toThrow()
})

test('fallos de identidad no confiable y prekey ausente no consumen el mensaje', async () => {
  const aId = keyhelper.generateIdentityKeyPair()
  const bId = keyhelper.generateIdentityKeyPair()
  const bSigned = keyhelper.generateSignedPreKey(bId, 4)
  const bPre = keyhelper.generatePreKey(5)
  const aStore = makeStore(aId, 30, null)
  const bStore = makeStore(bId, 40, bSigned, new Map())
  bStore.isTrustedIdentity = async () => false
  const bAddr = new ProtocolAddress('bob-errors', 1)
  const aAddr = new ProtocolAddress('alice-errors', 1)
  await new SessionBuilder(aStore, bAddr).initOutgoing(makeBundle(bId, 40, bSigned, bPre))
  const message = await new SessionCipher(aStore, bAddr).encrypt(Buffer.from('hello'))
  const bob = new SessionCipher(bStore, aAddr)
  const wire = Buffer.from(message.body, 'binary')
  await expect(bob.decryptPreKeyWhisperMessage(wire)).rejects.toThrow()
  bStore.isTrustedIdentity = async () => true
  await expect(bob.decryptPreKeyWhisperMessage(wire)).rejects.toThrow()
  expect(await bob.hasOpenSession()).toBe(false)
})

test('bundle sin prekey de un solo uso funciona y firmas alteradas se rechazan', async () => {
  const aId = keyhelper.generateIdentityKeyPair()
  const bId = keyhelper.generateIdentityKeyPair()
  const bSigned = keyhelper.generateSignedPreKey(bId, 8)
  const alice = makeStore(aId, 70, null)
  const bob = makeStore(bId, 80, bSigned)
  const bAddr = new ProtocolAddress('bob-no-opk', 1)
  const aAddr = new ProtocolAddress('alice-no-opk', 1)
  const builder = new SessionBuilder(alice, bAddr)
  const bundle = makeBundle(bId, 80, bSigned, null)
  const forgedBundle = {
    ...bundle,
    signedPreKey: {
      ...bundle.signedPreKey,
      signature: Buffer.from(bundle.signedPreKey.signature),
    },
  }
  forgedBundle.signedPreKey.signature[0] ^= 1
  await expect(builder.initOutgoing(forgedBundle)).rejects.toThrow(/signature/i)
  expect(await alice.loadSession(bAddr.toString())).toBeUndefined()

  await builder.initOutgoing(bundle)
  const a = new SessionCipher(alice, bAddr)
  const b = new SessionCipher(bob, aAddr)
  const first = await a.encrypt(Buffer.from('sin prekey efimera'))
  expect(first.type).toBe(3)
  expect(await b.decryptPreKeyWhisperMessage(Buffer.from(first.body, 'binary')))
    .toEqual(Buffer.from('sin prekey efimera'))
  expect(bob.loadPreKey).toBeDefined()
  expect(await a.hasOpenSession()).toBe(true)
  expect(await b.hasOpenSession()).toBe(true)
})

test('alterar o ciphertext falha e não avanza el estado de sesión', async () => {
  const aId = keyhelper.generateIdentityKeyPair()
  const bId = keyhelper.generateIdentityKeyPair()
  const bSigned = keyhelper.generateSignedPreKey(bId, 6)
  const bPre = keyhelper.generatePreKey(7)
  const alice = makeStore(aId, 50, null)
  const bob = makeStore(bId, 60, bSigned, new Map([[7, bPre.keyPair]]))
  const bAddr = new ProtocolAddress('bob-tamper', 1)
  const aAddr = new ProtocolAddress('alice-tamper', 1)
  await new SessionBuilder(alice, bAddr).initOutgoing(makeBundle(bId, 60, bSigned, bPre))
  const a = new SessionCipher(alice, bAddr)
  const b = new SessionCipher(bob, aAddr)
  const initial = await a.encrypt(Buffer.from('inicio'))
  await b.decryptPreKeyWhisperMessage(Buffer.from(initial.body, 'binary'))
  const confirmation = await b.encrypt(Buffer.from('confirmacion'))
  await a.decryptWhisperMessage(Buffer.from(confirmation.body, 'binary'))
  const normal = await a.encrypt(Buffer.from('sin alterar'))
  const changed = Buffer.from(normal.body, 'binary')
  changed[changed.length - 1] ^= 1
  await expect(b.decryptWhisperMessage(changed)).rejects.toThrow()
  expect((await b.decryptWhisperMessage(Buffer.from(normal.body, 'binary'))).toString()).toBe('sin alterar')
})

test('direccion y registros manejan entradas invalidas y vacias', () => {
  expect(ProtocolAddress.from('user.12').toString()).toBe('user.12')
  expect(() => ProtocolAddress.from('user.no-device')).toThrow()
  expect(() => new ProtocolAddress('user.12', 1)).toThrow()
  expect(new SessionRecord().haveOpenSession()).toBe(false)
  expect(new SessionRecord().serialize()).toEqual(Buffer.alloc(0))
  expect(new SenderKeyRecord().isEmpty()).toBe(true)
  expect(new SenderKeyRecord().serialize()).toEqual(Buffer.alloc(0))
  expect(() => curve.createKeyPair(Buffer.alloc(31))).toThrow()
  expect(() => curve.verifySignature(Buffer.alloc(33), Buffer.alloc(0), Buffer.alloc(63))).toThrow()
})
