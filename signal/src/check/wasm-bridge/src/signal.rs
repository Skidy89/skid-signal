// velowa (https://github.com/7ucg/velowa) (c) 2026 Baron. Copying any part of this file, however small, requires credit: see LICENSE.
//! Signal protocol (X3DH, Double Ratchet, sender keys) over TS-owned storage.
//!
//! Storage stays in TS (default from TODO Phase 3): `SignalCipher` holds only a
//! reference to a JS `SignalStorage` object and awaits its methods, so Rust is
//! stateless between calls and the consumer picks where state lives.
//!
//! Durability (agent_docs/signal_durability.md): every state mutation is
//! written through `storeSession`/`storeSenderKey` and awaited *before* the
//! ciphertext/plaintext is returned, so a message key never reaches the wire
//! ahead of its persisted state. Records are (de)serialized with the plain,
//! incarnation-less format, which libsignal treats as a conservative "new
//! incarnation" on load: counters fast-forward to the stored reservation.
//! A decrypted pre-key message reports `preKeyId`; the caller must delete that
//! pre-key only after the session is durable (it already is when `decrypt`
//! resolves, since `storeSession` was awaited).

use js_sys::{Object, Reflect, Uint8Array};
use wacore_libsignal::protocol::GenericSignedPreKey;
use wacore_libsignal::protocol::{
    CiphertextMessage, CiphertextMessageType, Direction, IdentityChange, IdentityKey,
    IdentityKeyPair, IdentityKeyStore, PreKeyBundle, PreKeyId, PreKeyRecord, PreKeySignalMessage,
    PreKeyStore, PrivateKey, ProtocolAddress, PublicKey, SenderKeyDistributionMessage,
    SenderKeyName, SenderKeyRecord, SenderKeyStore, SessionRecord, SessionStore, SignalMessage,
    SignalProtocolError, SignedPreKeyId, SignedPreKeyRecord, SignedPreKeyStore, UsePQRatchet,
    create_sender_key_distribution_message, group_decrypt, group_encrypt, message_decrypt,
    message_encrypt, process_prekey_bundle, process_sender_key_distribution_message,
};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(typescript_custom_section)]
const TS_SIGNAL: &str = r#"
/** Persistence the consumer provides. All writes must be durable when the promise resolves. */
export interface SignalStorage {
  getIdentityKeyPair(): Promise<{ publicKey: Uint8Array; privateKey: Uint8Array }>;
  getLocalRegistrationId(): Promise<number>;
  loadIdentity(name: string, device: number): Promise<Uint8Array | undefined>;
  saveIdentity(name: string, device: number, identityKey: Uint8Array): Promise<void>;
  loadSession(name: string, device: number): Promise<Uint8Array | undefined>;
  storeSession(name: string, device: number, record: Uint8Array): Promise<void>;
  loadPreKey(id: number): Promise<Uint8Array | undefined>;
  storePreKey(id: number, record: Uint8Array): Promise<void>;
  removePreKey(id: number): Promise<void>;
  loadSignedPreKey(id: number): Promise<Uint8Array | undefined>;
  storeSignedPreKey(id: number, record: Uint8Array): Promise<void>;
  loadSenderKey(key: string): Promise<Uint8Array | undefined>;
  storeSenderKey(key: string, record: Uint8Array): Promise<void>;
}

/** A device's pre-key bundle as WhatsApp delivers it (32-byte raw X25519 keys). */
export interface PreKeyBundleInput {
  registrationId: number;
  deviceId: number;
  preKeyId?: number;
  preKeyPublic?: Uint8Array;
  signedPreKeyId: number;
  signedPreKeyPublic: Uint8Array;
  signedPreKeySignature: Uint8Array;
  identityKey: Uint8Array;
}

export interface EncryptedMessage { type: 'msg' | 'pkmsg'; ciphertext: Uint8Array }
export interface DecryptedMessage { plaintext: Uint8Array; preKeyId?: number; identityChanged: boolean }
"#;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "SignalStorage")]
    pub type JsSignalStorage;
    #[wasm_bindgen(typescript_type = "PreKeyBundleInput")]
    pub type JsPreKeyBundleInput;
    #[wasm_bindgen(typescript_type = "EncryptedMessage")]
    pub type JsEncryptedMessage;
    #[wasm_bindgen(typescript_type = "DecryptedMessage")]
    pub type JsDecryptedMessage;

    #[wasm_bindgen(method, catch, js_name = getIdentityKeyPair)]
    async fn get_identity_key_pair(this: &JsSignalStorage) -> Result<JsValue, JsValue>;
    #[wasm_bindgen(method, catch, js_name = getLocalRegistrationId)]
    async fn get_local_registration_id(this: &JsSignalStorage) -> Result<JsValue, JsValue>;
    #[wasm_bindgen(method, catch, js_name = loadIdentity)]
    async fn load_identity(
        this: &JsSignalStorage,
        name: &str,
        device: u32,
    ) -> Result<JsValue, JsValue>;
    #[wasm_bindgen(method, catch, js_name = saveIdentity)]
    async fn save_identity(
        this: &JsSignalStorage,
        name: &str,
        device: u32,
        key: &Uint8Array,
    ) -> Result<JsValue, JsValue>;
    #[wasm_bindgen(method, catch, js_name = loadSession)]
    async fn load_session(
        this: &JsSignalStorage,
        name: &str,
        device: u32,
    ) -> Result<JsValue, JsValue>;
    #[wasm_bindgen(method, catch, js_name = storeSession)]
    async fn store_session(
        this: &JsSignalStorage,
        name: &str,
        device: u32,
        record: &Uint8Array,
    ) -> Result<JsValue, JsValue>;
    #[wasm_bindgen(method, catch, js_name = loadPreKey)]
    async fn load_pre_key(this: &JsSignalStorage, id: u32) -> Result<JsValue, JsValue>;
    #[wasm_bindgen(method, catch, js_name = storePreKey)]
    async fn store_pre_key(
        this: &JsSignalStorage,
        id: u32,
        record: &Uint8Array,
    ) -> Result<JsValue, JsValue>;
    #[wasm_bindgen(method, catch, js_name = removePreKey)]
    async fn remove_pre_key(this: &JsSignalStorage, id: u32) -> Result<JsValue, JsValue>;
    #[wasm_bindgen(method, catch, js_name = loadSignedPreKey)]
    async fn load_signed_pre_key(this: &JsSignalStorage, id: u32) -> Result<JsValue, JsValue>;
    #[wasm_bindgen(method, catch, js_name = storeSignedPreKey)]
    async fn store_signed_pre_key(
        this: &JsSignalStorage,
        id: u32,
        record: &Uint8Array,
    ) -> Result<JsValue, JsValue>;
    #[wasm_bindgen(method, catch, js_name = loadSenderKey)]
    async fn load_sender_key(this: &JsSignalStorage, key: &str) -> Result<JsValue, JsValue>;
    #[wasm_bindgen(method, catch, js_name = storeSenderKey)]
    async fn store_sender_key(
        this: &JsSignalStorage,
        key: &str,
        record: &Uint8Array,
    ) -> Result<JsValue, JsValue>;
}

type SResult<T> = Result<T, SignalProtocolError>;

fn store_err(what: &str, e: JsValue) -> SignalProtocolError {
    let msg = e
        .as_string()
        .or_else(|| {
            Reflect::get(&e, &"message".into())
                .ok()
                .and_then(|m| m.as_string())
        })
        .or_else(|| js_sys::JSON::stringify(&e).ok().and_then(|s| s.as_string()))
        .unwrap_or_else(|| "unknown error".into());
    SignalProtocolError::InvalidState("storage", format!("{what}: {msg}"))
}

/// Copy into a fresh JS-owned buffer: a `&[u8]` argument would be a view into wasm memory that
/// is only valid for the duration of the call, which a storage backend must not have to know.
fn owned(b: &[u8]) -> Uint8Array {
    Uint8Array::from(b)
}

fn bytes_of(v: &JsValue) -> Option<Vec<u8>> {
    if v.is_undefined() || v.is_null() {
        None
    } else {
        Some(Uint8Array::new(v).to_vec())
    }
}

fn with_type_prefix(raw: &[u8]) -> Vec<u8> {
    if raw.len() == 32 {
        let mut v = Vec::with_capacity(33);
        v.push(0x05);
        v.extend_from_slice(raw);
        v
    } else {
        raw.to_vec()
    }
}

/// JS-backed implementation of every store trait libsignal needs.
struct JsStore {
    js: JsSignalStorage,
}

#[async_trait::async_trait(?Send)]
impl IdentityKeyStore for JsStore {
    async fn get_identity_key_pair(&self) -> SResult<IdentityKeyPair> {
        let kp = self
            .js
            .get_identity_key_pair()
            .await
            .map_err(|e| store_err("getIdentityKeyPair", e))?;
        let private = Reflect::get(&kp, &"privateKey".into())
            .ok()
            .and_then(|v| bytes_of(&v));
        let private = private.ok_or_else(|| {
            SignalProtocolError::InvalidState("storage", "identity privateKey missing".into())
        })?;
        IdentityKeyPair::try_from(PrivateKey::deserialize(&private)?)
    }

    async fn get_local_registration_id(&self) -> SResult<u32> {
        let v = self
            .js
            .get_local_registration_id()
            .await
            .map_err(|e| store_err("getLocalRegistrationId", e))?;
        v.as_f64().map(|f| f as u32).ok_or_else(|| {
            SignalProtocolError::InvalidState("storage", "registration id not a number".into())
        })
    }

    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> SResult<IdentityChange> {
        let existing = self.get_identity(address).await?;
        let changed = existing.as_ref().is_some_and(|e| e != identity);
        self.js
            .save_identity(
                address.name(),
                address.device_id().into(),
                &owned(&identity.serialize()),
            )
            .await
            .map_err(|e| store_err("saveIdentity", e))?;
        Ok(IdentityChange::from_changed(changed))
    }

    // Trust on first use, like WhatsApp Web: a changed identity is accepted and surfaced
    // via `identityChanged` so the application layer can warn / re-verify.
    async fn is_trusted_identity(
        &self,
        _address: &ProtocolAddress,
        _identity: &IdentityKey,
        _direction: Direction,
    ) -> SResult<bool> {
        Ok(true)
    }

    async fn get_identity(&self, address: &ProtocolAddress) -> SResult<Option<IdentityKey>> {
        let v = self
            .js
            .load_identity(address.name(), address.device_id().into())
            .await
            .map_err(|e| store_err("loadIdentity", e))?;
        bytes_of(&v).map(|b| IdentityKey::decode(&b)).transpose()
    }
}

#[async_trait::async_trait(?Send)]
impl PreKeyStore for JsStore {
    async fn get_pre_key(&self, id: PreKeyId) -> SResult<PreKeyRecord> {
        let v = self
            .js
            .load_pre_key(id.into())
            .await
            .map_err(|e| store_err("loadPreKey", e))?;
        match bytes_of(&v) {
            Some(b) => PreKeyRecord::deserialize(&b),
            None => Err(SignalProtocolError::InvalidPreKeyId),
        }
    }
    async fn save_pre_key(&mut self, id: PreKeyId, record: &PreKeyRecord) -> SResult<()> {
        self.js
            .store_pre_key(id.into(), &owned(&record.serialize()?))
            .await
            .map_err(|e| store_err("storePreKey", e))?;
        Ok(())
    }
    async fn remove_pre_key(&mut self, id: PreKeyId) -> SResult<()> {
        self.js
            .remove_pre_key(id.into())
            .await
            .map_err(|e| store_err("removePreKey", e))?;
        Ok(())
    }
}

#[async_trait::async_trait(?Send)]
impl SignedPreKeyStore for JsStore {
    async fn get_signed_pre_key(&self, id: SignedPreKeyId) -> SResult<SignedPreKeyRecord> {
        let v = self
            .js
            .load_signed_pre_key(id.into())
            .await
            .map_err(|e| store_err("loadSignedPreKey", e))?;
        match bytes_of(&v) {
            Some(b) => SignedPreKeyRecord::deserialize(&b),
            None => Err(SignalProtocolError::InvalidSignedPreKeyId),
        }
    }
    async fn save_signed_pre_key(
        &mut self,
        id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
    ) -> SResult<()> {
        self.js
            .store_signed_pre_key(id.into(), &owned(&record.serialize()?))
            .await
            .map_err(|e| store_err("storeSignedPreKey", e))?;
        Ok(())
    }
}

#[async_trait::async_trait(?Send)]
impl SessionStore for JsStore {
    async fn load_session(&self, address: &ProtocolAddress) -> SResult<Option<SessionRecord>> {
        let v = self
            .js
            .load_session(address.name(), address.device_id().into())
            .await
            .map_err(|e| store_err("loadSession", e))?;
        // An undecodable row is reported absent (see signal_durability.md): the next
        // pre-key message must be able to replace it.
        Ok(bytes_of(&v).and_then(|b| SessionRecord::deserialize(&b).ok()))
    }
    async fn has_session(&self, address: &ProtocolAddress) -> SResult<bool> {
        Ok(self.load_session(address).await?.is_some())
    }
    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: SessionRecord,
    ) -> SResult<()> {
        self.js
            .store_session(
                address.name(),
                address.device_id().into(),
                &owned(&record.serialize()?),
            )
            .await
            .map_err(|e| store_err("storeSession", e))?;
        Ok(())
    }
}

#[async_trait::async_trait(?Send)]
impl SenderKeyStore for JsStore {
    async fn store_sender_key(
        &mut self,
        name: &SenderKeyName,
        record: SenderKeyRecord,
    ) -> SResult<()> {
        self.js
            .store_sender_key(&sender_key_id(name), &owned(&record.serialize()?))
            .await
            .map_err(|e| store_err("storeSenderKey", e))?;
        Ok(())
    }
    async fn load_sender_key(&self, name: &SenderKeyName) -> SResult<Option<SenderKeyRecord>> {
        let v = self
            .js
            .load_sender_key(&sender_key_id(name))
            .await
            .map_err(|e| store_err("loadSenderKey", e))?;
        bytes_of(&v)
            .map(|b| SenderKeyRecord::deserialize(&b))
            .transpose()
    }
}

fn sender_key_id(name: &SenderKeyName) -> String {
    format!("{}::{}", name.group_id(), name.sender_id())
}

fn err(e: impl std::fmt::Display) -> JsError {
    JsError::new(&e.to_string())
}

fn addr(name: &str, device: u32) -> ProtocolAddress {
    ProtocolAddress::new(name, device.into())
}

fn field(obj: &JsValue, key: &str) -> JsValue {
    Reflect::get(obj, &JsValue::from_str(key)).unwrap_or(JsValue::UNDEFINED)
}

fn req_bytes(obj: &JsValue, key: &str) -> Result<Vec<u8>, JsError> {
    bytes_of(&field(obj, key)).ok_or_else(|| err(format!("bundle.{key} missing")))
}

fn req_u32(obj: &JsValue, key: &str) -> Result<u32, JsError> {
    field(obj, key)
        .as_f64()
        .map(|f| f as u32)
        .ok_or_else(|| err(format!("bundle.{key} must be a number")))
}

fn parse_bundle(b: &JsValue) -> Result<PreKeyBundle, JsError> {
    let pre_key = match (
        field(b, "preKeyId").as_f64(),
        bytes_of(&field(b, "preKeyPublic")),
    ) {
        (Some(id), Some(public)) => Some((
            PreKeyId::from(id as u32),
            PublicKey::try_from(with_type_prefix(&public).as_slice()).map_err(err)?,
        )),
        _ => None,
    };
    PreKeyBundle::new(
        req_u32(b, "registrationId")?,
        req_u32(b, "deviceId")?.into(),
        pre_key,
        SignedPreKeyId::from(req_u32(b, "signedPreKeyId")?),
        PublicKey::try_from(with_type_prefix(&req_bytes(b, "signedPreKeyPublic")?).as_slice())
            .map_err(err)?,
        req_bytes(b, "signedPreKeySignature")?,
        IdentityKey::decode(&with_type_prefix(&req_bytes(b, "identityKey")?)).map_err(err)?,
    )
    .map_err(err)
}

/// Signal sessions and group ciphers bound to a consumer-provided `SignalStorage`.
#[wasm_bindgen]
pub struct SignalCipher {
    store: JsStore,
}

#[wasm_bindgen]
impl SignalCipher {
    #[wasm_bindgen(constructor)]
    pub fn new(storage: JsSignalStorage) -> SignalCipher {
        SignalCipher {
            store: JsStore { js: storage },
        }
    }

    /// Establish an outgoing session from a device's pre-key bundle (X3DH).
    #[wasm_bindgen(js_name = processPreKeyBundle)]
    pub async fn process_pre_key_bundle(
        &mut self,
        name: &str,
        device: u32,
        bundle: JsPreKeyBundleInput,
    ) -> Result<bool, JsError> {
        let bundle = parse_bundle(&bundle)?;
        let address = addr(name, device);
        let mut identity = JsStore {
            js: self.store.js.clone().unchecked_into(),
        };
        let change = process_prekey_bundle(
            &address,
            &mut self.store,
            &mut identity,
            &bundle,
            &mut rand::rng(),
            UsePQRatchet::No,
        )
        .await
        .map_err(err)?;
        Ok(change == IdentityChange::ReplacedExisting)
    }

    /// Whether a session with this device exists.
    #[wasm_bindgen(js_name = hasSession)]
    pub async fn has_session(&self, name: &str, device: u32) -> Result<bool, JsError> {
        SessionStore::has_session(&self.store, &addr(name, device))
            .await
            .map_err(err)
    }

    /// Double-Ratchet encrypt. The session is persisted before this resolves.
    pub async fn encrypt(
        &mut self,
        name: &str,
        device: u32,
        plaintext: &[u8],
    ) -> Result<JsEncryptedMessage, JsError> {
        let address = addr(name, device);
        let mut identity = JsStore {
            js: self.store.js.clone().unchecked_into(),
        };
        let msg = message_encrypt(plaintext, &address, &mut self.store, &mut identity)
            .await
            .map_err(err)?;
        let ty = match msg.message_type() {
            CiphertextMessageType::PreKey => "pkmsg",
            _ => "msg",
        };
        let out = Object::new();
        set(&out, "type", &JsValue::from_str(ty));
        set(&out, "ciphertext", &Uint8Array::from(msg.serialize()));
        Ok(out.unchecked_into())
    }

    /// Decrypt a `msg` / `pkmsg` envelope. The updated session is persisted before this resolves;
    /// `preKeyId` (pkmsg only) is then safe to delete.
    pub async fn decrypt(
        &mut self,
        name: &str,
        device: u32,
        kind: &str,
        ciphertext: &[u8],
    ) -> Result<JsDecryptedMessage, JsError> {
        let address = addr(name, device);
        let message = match kind {
            "msg" => {
                CiphertextMessage::SignalMessage(SignalMessage::try_from(ciphertext).map_err(err)?)
            }
            "pkmsg" => CiphertextMessage::PreKeySignalMessage(
                PreKeySignalMessage::try_from(ciphertext).map_err(err)?,
            ),
            other => return Err(err(format!("unknown ciphertext type '{other}'"))),
        };
        let mut identity = JsStore {
            js: self.store.js.clone().unchecked_into(),
        };
        let mut pre_keys = JsStore {
            js: self.store.js.clone().unchecked_into(),
        };
        let signed = JsStore {
            js: self.store.js.clone().unchecked_into(),
        };
        let res = message_decrypt(
            &message,
            &address,
            &mut self.store,
            &mut identity,
            &mut pre_keys,
            &signed,
            &mut rand::rng(),
            UsePQRatchet::No,
        )
        .await
        .map_err(err)?;
        let out = Object::new();
        set(
            &out,
            "plaintext",
            &Uint8Array::from(res.plaintext.as_slice()),
        );
        if let Some(id) = res.consumed_prekey_id {
            set(&out, "preKeyId", &JsValue::from_f64(u32::from(id) as f64));
        }
        set(
            &out,
            "identityChanged",
            &JsValue::from_bool(res.identity_change == IdentityChange::ReplacedExisting),
        );
        Ok(out.unchecked_into())
    }

    /// Create (or re-export) our sender-key distribution message for a group.
    #[wasm_bindgen(js_name = createSenderKeyDistribution)]
    pub async fn create_sender_key_distribution(
        &mut self,
        group: &str,
        sender: &str,
    ) -> Result<Vec<u8>, JsError> {
        let name = SenderKeyName::from_parts(group, sender);
        let skdm = create_sender_key_distribution_message(&name, &mut self.store, &mut rand::rng())
            .await
            .map_err(err)?;
        Ok(skdm.serialized().to_vec())
    }

    /// Process a received sender-key distribution message.
    #[wasm_bindgen(js_name = processSenderKeyDistribution)]
    pub async fn process_sender_key_distribution(
        &mut self,
        group: &str,
        sender: &str,
        skdm: &[u8],
    ) -> Result<(), JsError> {
        let name = SenderKeyName::from_parts(group, sender);
        let skdm = SenderKeyDistributionMessage::try_from(skdm).map_err(err)?;
        process_sender_key_distribution_message(&name, &skdm, &mut self.store)
            .await
            .map_err(err)
    }

    /// Group (sender-key) encrypt. Create the distribution message first.
    #[wasm_bindgen(js_name = groupEncrypt)]
    pub async fn group_encrypt(
        &mut self,
        group: &str,
        sender: &str,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        let name = SenderKeyName::from_parts(group, sender);
        let msg = group_encrypt(&mut self.store, &name, plaintext, &mut rand::rng())
            .await
            .map_err(err)?;
        Ok(msg.serialized().to_vec())
    }

    /// Group (sender-key) decrypt of an `skmsg`.
    #[wasm_bindgen(js_name = groupDecrypt)]
    pub async fn group_decrypt(
        &mut self,
        group: &str,
        sender: &str,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        let name = SenderKeyName::from_parts(group, sender);
        group_decrypt(ciphertext, &mut self.store, &name)
            .await
            .map_err(err)
    }
}

fn set(o: &Object, k: &str, v: &JsValue) {
    let _ = Reflect::set(o, &JsValue::from_str(k), v);
}

/// Fresh identity key pair (raw 32-byte X25519 keys) for a new device.
#[wasm_bindgen(js_name = generateIdentityKeyPair)]
pub fn generate_identity_key_pair() -> JsValue {
    let kp = wacore_libsignal::protocol::KeyPair::generate(&mut rand::rng());
    let out = Object::new();
    set(
        &out,
        "publicKey",
        &Uint8Array::from(kp.public_key.public_key_bytes()),
    );
    set(
        &out,
        "privateKey",
        &Uint8Array::from(&kp.private_key.serialize()[..]),
    );
    out.into()
}

/// Signed pre-key signed by the identity private key; `record` is what `SignalStorage.storeSignedPreKey` persists.
#[wasm_bindgen(js_name = generateSignedPreKey)]
pub fn generate_signed_pre_key(identity_private: &[u8], id: u32) -> Result<JsValue, JsError> {
    let identity = PrivateKey::deserialize(identity_private).map_err(err)?;
    let kp = wacore_libsignal::protocol::KeyPair::generate(&mut rand::rng());
    let signature = identity
        .calculate_signature(&kp.public_key.serialize(), &mut rand::rng())
        .map_err(err)?;
    let record = SignedPreKeyRecord::new(
        SignedPreKeyId::from(id),
        wacore_libsignal::protocol::Timestamp::from_epoch_millis(js_sys::Date::now() as u64),
        &kp,
        &signature,
    );
    let out = Object::new();
    set(&out, "id", &JsValue::from_f64(id as f64));
    set(
        &out,
        "record",
        &Uint8Array::from(record.serialize().map_err(err)?.as_slice()),
    );
    set(
        &out,
        "publicKey",
        &Uint8Array::from(kp.public_key.public_key_bytes()),
    );
    set(&out, "signature", &Uint8Array::from(&signature[..]));
    Ok(out.into())
}

/// `count` one-time pre-keys with ids `start..start+count`: `{ id, record, publicKey }[]`.
#[wasm_bindgen(js_name = generatePreKeys)]
pub fn generate_pre_keys(start: u32, count: u32) -> Result<js_sys::Array, JsError> {
    let arr = js_sys::Array::new();
    for id in start
        ..start
            .checked_add(count)
            .ok_or_else(|| err("pre-key id overflow"))?
    {
        let kp = wacore_libsignal::protocol::KeyPair::generate(&mut rand::rng());
        let record = PreKeyRecord::new(PreKeyId::from(id), &kp);
        let o = Object::new();
        set(&o, "id", &JsValue::from_f64(id as f64));
        set(
            &o,
            "record",
            &Uint8Array::from(record.serialize().map_err(err)?.as_slice()),
        );
        set(
            &o,
            "publicKey",
            &Uint8Array::from(kp.public_key.public_key_bytes()),
        );
        arr.push(&o);
    }
    Ok(arr)
}

/// XEdDSA signature (64 bytes) over `message` with a raw 32-byte X25519 private key.
#[wasm_bindgen(js_name = curveSign)]
pub fn curve_sign(private_key: &[u8], message: &[u8]) -> Result<Vec<u8>, JsError> {
    let key = PrivateKey::deserialize(private_key).map_err(err)?;
    Ok(key
        .calculate_signature(message, &mut rand::rng())
        .map_err(err)?
        .to_vec())
}

/// Verify an XEdDSA signature against a raw 32-byte (or type-prefixed 33-byte) public key.
#[wasm_bindgen(js_name = curveVerify)]
pub fn curve_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    PublicKey::try_from(with_type_prefix(public_key).as_slice())
        .map(|k| k.verify_signature(message, signature))
        .unwrap_or(false)
}
