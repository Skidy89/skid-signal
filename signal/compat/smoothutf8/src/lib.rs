#![no_std]

pub const SLACK: usize = 0;

#[inline]
pub fn from_utf8(bytes: &[u8]) -> Option<&str> {
    core::str::from_utf8(bytes).ok()
}

#[inline]
pub fn verify(bytes: &[u8]) -> bool {
    core::str::from_utf8(bytes).is_ok()
}

#[inline]
pub unsafe fn verify_with_slack(bytes: &[u8], range: core::ops::Range<usize>) -> bool {
    verify(&bytes[range])
}
