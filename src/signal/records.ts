import * as native from "../../native";
import {
  isLegacySenderKeyRecord,
  migrateLegacySenderKeyRecord,
} from "./legacy";
import { Bytes, recordBytes } from "./util";

export class SessionRecord {
  readonly raw: Buffer | undefined;

  constructor(data?: Bytes | null) {
    this.raw = recordBytes(data) ?? undefined;
  }

  static deserialize(data: Bytes): SessionRecord {
    return new SessionRecord(data);
  }

  serialize(): Buffer {
    return this.raw ?? Buffer.alloc(0);
  }

  haveOpenSession(): boolean {
    return !!this.raw && native.sessionHaveOpen(this.raw);
  }
}

export class SenderKeyRecord {
  readonly raw: Buffer | undefined;

  constructor(data?: Bytes | null) {
    const b = recordBytes(data);
    this.raw = b
      ? ((isLegacySenderKeyRecord(b) ? migrateLegacySenderKeyRecord(b) : b) ??
        undefined)
      : undefined;
  }

  static deserialize(data: Bytes): SenderKeyRecord {
    return new SenderKeyRecord(data);
  }

  isEmpty(): boolean {
    return !this.raw;
  }

  serialize(): Buffer {
    return this.raw ?? Buffer.alloc(0);
  }
}
