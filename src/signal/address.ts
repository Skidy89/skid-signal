export class ProtocolAddress {
  static from(encoded: string): ProtocolAddress {
    const i = typeof encoded === "string" ? encoded.lastIndexOf(".") : -1;
    const deviceId = i > 0 ? Number(encoded.slice(i + 1)) : NaN;
    if (!Number.isInteger(deviceId))
      throw new Error("Invalid address encoding");
    return new ProtocolAddress(encoded.slice(0, i), deviceId);
  }

  constructor(
    readonly id: string,
    readonly deviceId: number,
  ) {
    if (typeof id !== "string") throw new TypeError("id required for addr");
    if (id.includes(".")) throw new TypeError("encoded addr detected");
    if (typeof deviceId !== "number")
      throw new TypeError("number required for deviceId");
  }

  toString(): string {
    return `${this.id}.${this.deviceId}`;
  }

  is(other: ProtocolAddress): boolean {
    return (
      other instanceof ProtocolAddress &&
      other.id === this.id &&
      other.deviceId === this.deviceId
    );
  }
}
