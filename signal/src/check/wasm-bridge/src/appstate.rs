// velowa (https://github.com/7ucg/velowa) (c) 2026 Baron. Copying any part of this file, however small, requires credit: see LICENSE.
//! App-state (syncd) crypto: LTHash, patch / snapshot MAC validation and mutation decryption.
//!
//! `AppStateCollection` owns the hash state of one collection (`regular`, `critical_block`, ...).
//! Orchestration (which collections to sync, when, retries, turning mutations into events) stays
//! in TS; this class is only the math. Patches are applied transactionally: the state is cloned,
//! the patch folded into the clone and committed only on success, so a rejected patch never
//! leaves a half-updated LTHash behind.
//!
//! Key lookup is a synchronous TS callback `(keyId) => 32-byte key data | undefined`; the HKDF
//! expansion happens here.
//!
//! Mutation values are returned as encoded `SyncActionValue` protobuf bytes: TS holds the full
//! WAProto schema and decodes them, so Rust need not mirror 35+ message types across the boundary.

use js_sys::{Array, Function, Object, Reflect, Uint8Array};
use std::sync::Arc;
use wacore_appstate::encode::encode_record;
use wacore_appstate::hash::{HashState, generate_patch_mac};
use wacore_appstate::processor::{AppStateMutationMAC, process_patch, process_snapshot};
use wacore_appstate::{AppStateError, ExpandedAppStateKeys, Mutation, expand_app_state_keys};
use waproto::whatsapp as wa;
use waproto::whatsapp::syncd_mutation::SyncdOperation;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(typescript_custom_section)]
const TS_APPSTATE: &str = r#"
/** Resolve an app-state sync key by id; return the 32-byte key data or undefined. */
export type AppStateKeyLookup = (keyId: Uint8Array) => Uint8Array | undefined;
/** Value MAC of the previous SET for an index MAC, or undefined if none is stored. */
export type PreviousValueMacLookup = (indexMac: Uint8Array) => Uint8Array | undefined;

export interface AppStateMutation {
  /** Index components, e.g. ["mute", "123@s.whatsapp.net"]. */
  index: string[];
  operation: 'set' | 'remove';
  /** Encoded SyncActionValue protobuf (absent for a bare remove). */
  value?: Uint8Array;
}
export interface AppStateMac { indexMac: Uint8Array; valueMac: Uint8Array }
export interface AppStateResult {
  mutations: AppStateMutation[];
  /** MACs to persist so later patches can resolve REMOVEs. */
  addedMacs: AppStateMac[];
  /** Index MACs whose stored value MAC must be deleted. */
  removedIndexMacs: Uint8Array[];
}
"#;

#[wasm_bindgen(typescript_custom_section)]
const TS_APPSTATE_OUT: &str = r#"
/** One change to send to the other devices. `index` is the JSON-encoded index array. */
export interface OutgoingMutation {
  operation: 'set' | 'remove';
  /** e.g. JSON.stringify(['archive', '4915...@s.whatsapp.net']) */
  index: string;
  /** Encoded SyncActionValue protobuf. */
  value: Uint8Array;
  /** The action's schema version (WA Web stamps each action type; most are 2, labels 3). */
  version: number;
}
export interface BuiltPatch {
  /** Encoded SyncdPatch to put into the `<patch>` node. */
  patch: Uint8Array;
  version: number;
  addedMacs: AppStateMac[];
  removedIndexMacs: Uint8Array[];
}
"#;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "OutgoingMutation[]")]
    pub type JsOutgoingMutations;
    #[wasm_bindgen(typescript_type = "BuiltPatch")]
    pub type JsBuiltPatch;
    #[wasm_bindgen(typescript_type = "AppStateKeyLookup")]
    pub type JsKeyLookup;
    #[wasm_bindgen(typescript_type = "PreviousValueMacLookup")]
    pub type JsMacLookup;
    #[wasm_bindgen(typescript_type = "AppStateResult")]
    pub type JsAppStateResult;
}

fn err(e: impl std::fmt::Display) -> JsError {
    JsError::new(&e.to_string())
}

fn set(o: &Object, k: &str, v: &JsValue) {
    let _ = Reflect::set(o, &JsValue::from_str(k), v);
}

fn call1(f: &JsValue, arg: &[u8]) -> Result<JsValue, ()> {
    let f: &Function = f.unchecked_ref();
    f.call1(&JsValue::NULL, &Uint8Array::from(arg))
        .map_err(|_| ())
}

fn lookup_keys(f: &JsValue, key_id: &[u8]) -> Result<Arc<ExpandedAppStateKeys>, AppStateError> {
    let v = call1(f, key_id).map_err(|_| AppStateError::KeyNotFound)?;
    if v.is_undefined() || v.is_null() {
        return Err(AppStateError::KeyNotFound);
    }
    Ok(Arc::new(expand_app_state_keys(
        &Uint8Array::new(&v).to_vec(),
    )))
}

fn mac_obj(m: &AppStateMutationMAC) -> JsValue {
    let o = Object::new();
    set(&o, "indexMac", &Uint8Array::from(m.index_mac.as_slice()));
    set(&o, "valueMac", &Uint8Array::from(m.value_mac.as_slice()));
    o.into()
}

fn mutation_obj(m: &Mutation) -> JsValue {
    let o = Object::new();
    let index = Array::new();
    for part in &m.index {
        index.push(&JsValue::from_str(part));
    }
    set(&o, "index", &index);
    let op = if m.operation == SyncdOperation::REMOVE {
        "remove"
    } else {
        "set"
    };
    set(&o, "operation", &JsValue::from_str(op));
    if let Some(v) = &m.action_value {
        set(
            &o,
            "value",
            &Uint8Array::from(waproto::codec::sync_action_value_to_vec(v).as_slice()),
        );
    }
    o.into()
}

fn result_obj(
    mutations: &[Mutation],
    added: &[AppStateMutationMAC],
    removed: &[Vec<u8>],
) -> JsAppStateResult {
    let out = Object::new();
    let muts = Array::new();
    for m in mutations {
        muts.push(&mutation_obj(m));
    }
    let macs = Array::new();
    for m in added {
        macs.push(&mac_obj(m));
    }
    let rem = Array::new();
    for r in removed {
        rem.push(&Uint8Array::from(r.as_slice()));
    }
    set(&out, "mutations", &muts);
    set(&out, "addedMacs", &macs);
    set(&out, "removedIndexMacs", &rem);
    out.unchecked_into()
}

/// Hash state + MAC verification for one app-state collection.
#[wasm_bindgen]
pub struct AppStateCollection {
    name: String,
    state: HashState,
    /// State after an outgoing patch built by `buildPatch`, applied by `commitPending`.
    pending: Option<HashState>,
}

#[wasm_bindgen]
impl AppStateCollection {
    /// A fresh, never-synced collection.
    #[wasm_bindgen(constructor)]
    pub fn new(name: &str) -> AppStateCollection {
        AppStateCollection {
            name: name.to_owned(),
            state: HashState::default(),
            pending: None,
        }
    }

    /// Restore from bytes produced by `serializeState`.
    #[wasm_bindgen(js_name = fromState)]
    pub fn from_state(name: &str, state: &[u8]) -> Result<AppStateCollection, JsError> {
        let state = serde_json::from_slice(state).map_err(err)?;
        Ok(AppStateCollection {
            name: name.to_owned(),
            state,
            pending: None,
        })
    }

    /// Opaque bytes to persist; feed back to `fromState`.
    #[wasm_bindgen(js_name = serializeState)]
    pub fn serialize_state(&self) -> Result<Vec<u8>, JsError> {
        serde_json::to_vec(&self.state).map_err(err)
    }

    #[wasm_bindgen(getter)]
    pub fn name(&self) -> String {
        self.name.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn version(&self) -> f64 {
        self.state.version as f64
    }

    /// 128-byte LTHash.
    #[wasm_bindgen(getter)]
    pub fn hash(&self) -> Vec<u8> {
        self.state.hash.to_vec()
    }

    /// Apply an encoded `SyncdSnapshot`, rebuilding the collection from scratch.
    #[wasm_bindgen(js_name = applySnapshot)]
    pub fn apply_snapshot(
        &mut self,
        snapshot: &[u8],
        get_key: JsKeyLookup,
    ) -> Result<JsAppStateResult, JsError> {
        let snapshot = waproto::codec::syncd_snapshot_decode(snapshot).map_err(err)?;
        let get_key: JsValue = get_key.into();
        // Never roll a collection back: a replayed older snapshot would silently discard newer state.
        let snapshot_version = snapshot.version.version.unwrap_or(0);
        if snapshot_version < self.state.version {
            return Err(err(format!(
                "snapshot version {snapshot_version} is older than local version {}",
                self.state.version
            )));
        }
        let mut next = HashState::default();
        let out = process_snapshot(
            &snapshot,
            &mut next,
            |id| lookup_keys(&get_key, id),
            true,
            &self.name,
        )
        .map_err(err)?;
        // `process_snapshot` leaves the snapshot MAC check to the caller.
        let key_id = snapshot
            .key_id
            .id
            .as_deref()
            .ok_or_else(|| err(AppStateError::MissingKeyId))?;
        let keys = lookup_keys(&get_key, key_id).map_err(err)?;
        wacore_appstate::validate_snapshot_mac(&snapshot, &out.state, &keys, &self.name)
            .map_err(err)?;
        self.state = out.state;
        Ok(result_obj(&out.mutations, &out.mutation_macs, &[]))
    }

    /// Apply an encoded `SyncdPatch`. Transactional: on error the collection is unchanged.
    #[wasm_bindgen(js_name = applyPatch)]
    pub fn apply_patch(
        &mut self,
        patch: &[u8],
        get_key: JsKeyLookup,
        get_previous_value_mac: JsMacLookup,
    ) -> Result<JsAppStateResult, JsError> {
        let patch = waproto::codec::syncd_patch_decode(patch).map_err(err)?;
        let get_key: JsValue = get_key.into();
        let get_prev: JsValue = get_previous_value_mac.into();
        // Fail closed: without a top-level key id `process_patch` would skip both aggregate MACs.
        if patch.key_id.id.as_deref().is_none() {
            return Err(err(AppStateError::MissingKeyId));
        }
        // A patch cannot anchor the ltHash of a never-synced collection unless it is the genesis
        // patch; anything else needs a snapshot bootstrap first (and must not latch
        // `mac_mismatch_fatal` on an empty baseline).
        let patch_version = patch.version.version.unwrap_or(0);
        if self.state.version == 0 && self.state.hash == [0u8; 128] && patch_version != 1 {
            return Err(err(
                "collection has no baseline: apply a snapshot before non-genesis patches",
            ));
        }
        let mut next = self.state.clone();
        let out = process_patch(
            &patch,
            &mut next,
            |id| lookup_keys(&get_key, id),
            |index_mac| {
                let v = call1(&get_prev, index_mac)
                    .map_err(|_| AppStateError::MissingPreviousSetValueOperation)?;
                Ok(if v.is_undefined() || v.is_null() {
                    None
                } else {
                    Some(Uint8Array::new(&v).to_vec())
                })
            },
            true,
            &self.name,
        )
        .map_err(err)?;
        self.state = out.state;
        Ok(result_obj(
            &out.mutations,
            &out.added_macs,
            &out.removed_index_macs,
        ))
    }

    /// Build, encrypt and sign a patch carrying `mutations` on top of the current state. The new
    /// state is held as pending: call `commitPending()` once the server accepted the patch, or
    /// `discardPending()` if it did not.
    #[wasm_bindgen(js_name = buildPatch)]
    pub fn build_patch(
        &mut self,
        key_id: &[u8],
        key_data: &[u8],
        mutations: JsOutgoingMutations,
        get_previous_value_mac: JsMacLookup,
    ) -> Result<JsBuiltPatch, JsError> {
        use rand::Rng;
        let keys = expand_app_state_keys(key_data);
        let get_prev: JsValue = get_previous_value_mac.into();
        let list: Array = JsValue::from(mutations).unchecked_into();
        if list.length() == 0 {
            return Err(err("no mutations"));
        }
        let mut built = Vec::new();
        let mut added = Vec::new();
        let mut removed = Vec::new();
        for item in list.iter() {
            let op = match Reflect::get(&item, &"operation".into())
                .ok()
                .and_then(|v| v.as_string())
                .as_deref()
            {
                Some("set") => SyncdOperation::SET,
                Some("remove") => SyncdOperation::REMOVE,
                _ => return Err(err("operation must be 'set' or 'remove'")),
            };
            let index = Reflect::get(&item, &"index".into())
                .ok()
                .and_then(|v| v.as_string())
                .ok_or_else(|| err("index must be a JSON string"))?;
            let value_bytes = Uint8Array::new(
                &Reflect::get(&item, &"value".into()).map_err(|_| err("value missing"))?,
            )
            .to_vec();
            let version = Reflect::get(&item, &"version".into())
                .ok()
                .and_then(|v| v.as_f64())
                .unwrap_or(2.0) as i32;
            let value = waproto::codec::sync_action_value_decode(&value_bytes).map_err(err)?;
            let mut iv = [0u8; 16];
            rand::rng().fill_bytes(&mut iv);
            let (mutation, value_mac) =
                encode_record(op, index.as_bytes(), &value, &keys, key_id, &iv, version);
            let index_mac = mutation.record.index.blob.clone().unwrap_or_default();
            if op == SyncdOperation::SET {
                added.push((index_mac, value_mac.to_vec()));
            } else {
                removed.push(index_mac);
            }
            built.push(mutation);
        }

        let mut next = self.state.clone();
        let (_, folded) = next.update_hash(&built, |index_mac, _| {
            let v = call1(&get_prev, index_mac)
                .map_err(|_| anyhow::anyhow!("previous value lookup failed"))?;
            Ok(if v.is_undefined() || v.is_null() {
                None
            } else {
                Some(Uint8Array::new(&v).to_vec())
            })
        });
        folded.map_err(err)?;
        next.version += 1;

        let mut patch = wa::SyncdPatch {
            // No `version` field: the collection node carries the base version; Baileys' patches omit it too.
            mutations: built,
            key_id: buffa::MessageField::some(wa::KeyId {
                id: Some(key_id.to_vec()),
            }),
            snapshot_mac: Some(next.generate_snapshot_mac(&self.name, &keys.snapshot_mac)),
            ..Default::default()
        };
        patch.patch_mac = Some(generate_patch_mac(
            &patch,
            &self.name,
            &keys.patch_mac,
            next.version,
        ));

        let out = Object::new();
        set(
            &out,
            "patch",
            &Uint8Array::from(waproto::codec::syncd_patch_to_vec(&patch).as_slice()),
        );
        set(&out, "version", &JsValue::from_f64(next.version as f64));
        let macs = Array::new();
        for (i, v) in &added {
            let o = Object::new();
            set(&o, "indexMac", &Uint8Array::from(i.as_slice()));
            set(&o, "valueMac", &Uint8Array::from(v.as_slice()));
            macs.push(&o);
        }
        set(&out, "addedMacs", &macs);
        let rem = Array::new();
        for i in &removed {
            rem.push(&Uint8Array::from(i.as_slice()));
        }
        set(&out, "removedIndexMacs", &rem);
        self.pending = Some(next);
        Ok(out.unchecked_into())
    }

    /// The server accepted the patch from `buildPatch`: make its state current.
    #[wasm_bindgen(js_name = commitPending)]
    pub fn commit_pending(&mut self) -> Result<(), JsError> {
        self.state = self.pending.take().ok_or_else(|| err("no pending patch"))?;
        Ok(())
    }

    /// Drop the state from `buildPatch` (the server rejected the patch).
    #[wasm_bindgen(js_name = discardPending)]
    pub fn discard_pending(&mut self) {
        self.pending = None;
    }
}
