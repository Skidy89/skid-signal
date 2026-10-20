import * as native from "../../native";
import { ProtocolAddress } from "./address";
import { SenderKeyRecord } from "./records";
import { Bytes, MaybePromise, queueJob } from "./util";

export class SenderKeyName {
  constructor(
    readonly groupId: string,
    readonly sender: ProtocolAddress,
  ) {}
  serialize(): string {
    return `${this.groupId}::${this.sender.id}::${this.sender.deviceId}`;
  }
  toString(): string {
    return this.serialize();
  }
}

export class SenderKeyDistributionMessage {
  private readonly raw: Buffer;
  constructor(
    _id?: unknown,
    _iteration?: unknown,
    _chainKey?: unknown,
    _signingKey?: unknown,
    serialized?: Bytes,
  ) {
    if (!serialized)
      throw new Error(
        "SenderKeyDistributionMessage: only the serialized form is supported",
      );
    this.raw = serialized;
  }
  serialize(): Buffer {
    return this.raw;
  }
}

export type SenderKeyId = SenderKeyName | string;

export interface SenderKeyStore {
  loadSenderKey(
    name: SenderKeyId,
  ): MaybePromise<SenderKeyRecord | null | undefined>;
  storeSenderKey(
    name: SenderKeyId,
    record: SenderKeyRecord,
  ): MaybePromise<void>;
}

const lockKey = (n: SenderKeyId) => `sk:${String(n)}`;

export class GroupSessionBuilder {
  constructor(private readonly store: SenderKeyStore) {}

  create(name: SenderKeyId): Promise<SenderKeyDistributionMessage> {
    return queueJob(lockKey(name), async () => {
      const rec = await this.store.loadSenderKey(name);
      const { skdm, newRecord } =
        await native.groupCreateDistributionMessageAsync(rec?.raw ?? null);
      await this.store.storeSenderKey(name, new SenderKeyRecord(newRecord));
      return new SenderKeyDistributionMessage(null, null, null, null, skdm);
    });
  }

  process(
    name: SenderKeyId,
    msg: SenderKeyDistributionMessage | Bytes,
  ): Promise<void> {
    const bytes =
      msg instanceof SenderKeyDistributionMessage ? msg.serialize() : msg;
    return queueJob(lockKey(name), async () => {
      const rec = await this.store.loadSenderKey(name);
      const newRecord = await native.groupProcessDistributionMessageAsync(
        rec?.raw ?? null,
        bytes,
      );
      await this.store.storeSenderKey(name, new SenderKeyRecord(newRecord));
    });
  }
}

export class GroupCipher {
  constructor(
    private readonly store: SenderKeyStore,
    private readonly name: SenderKeyId,
  ) {}

  encrypt(plaintext: Bytes, legacyIterations = false): Promise<Buffer> {
    return queueJob(lockKey(this.name), async () => {
      const rec = await this.store.loadSenderKey(this.name);
      if (!rec?.raw) throw new Error("No session to encrypt message");
      const { ciphertext, newRecord } = await native.groupEncryptAsync(
        rec.raw,
        plaintext,
        legacyIterations,
      );
      await this.store.storeSenderKey(
        this.name,
        new SenderKeyRecord(newRecord),
      );
      return ciphertext;
    });
  }
  encryptWithSkdm(
    plaintext: Bytes,
    legacyIterations = false,
  ): Promise<{ ciphertext: Buffer; skdm: SenderKeyDistributionMessage }> {
    return queueJob(lockKey(this.name), async () => {
      const rec = await this.store.loadSenderKey(this.name);
      const { ciphertext, skdm, newRecord } =
        await native.groupEncryptWithSkdmAsync(
          rec?.raw ?? null,
          plaintext,
          legacyIterations,
        );
      await this.store.storeSenderKey(
        this.name,
        new SenderKeyRecord(newRecord),
      );
      return {
        ciphertext,
        skdm: new SenderKeyDistributionMessage(null, null, null, null, skdm),
      };
    });
  }

  decrypt(msg: Bytes): Promise<Buffer> {
    return queueJob(lockKey(this.name), async () => {
      const rec = await this.store.loadSenderKey(this.name);
      const { plaintext, newRecord } = await native.groupDecryptAsync(
        rec?.raw ?? null,
        msg,
      );
      await this.store.storeSenderKey(
        this.name,
        new SenderKeyRecord(newRecord),
      );
      return plaintext;
    });
  }
}
