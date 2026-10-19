export class SignalError extends Error {
  constructor(message: string) {
    super(message)
    this.name = new.target.name
  }
}
export class SessionError extends SignalError {}
export class PreKeyError extends SignalError {}
export class UntrustedIdentityKeyError extends SignalError {
  constructor(
    readonly addr: string,
    readonly identityKey: Buffer,
  ) {
    super('Untrusted identity key')
  }
}