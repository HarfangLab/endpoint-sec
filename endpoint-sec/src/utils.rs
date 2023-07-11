//! Utilities related to the handling of time, ect.

use std::borrow::Cow;
use std::ffi::{CStr, CString};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use mach2::mach_time::{mach_absolute_time, mach_timebase_info};

use crate::TimeError;

/// Convert a Mach absolute time to an [`Instant`].
pub(crate) fn convert_mach_time_to_instant(mach_time: u64) -> Result<Instant, TimeError> {
    let now = Instant::now();
    // Safety: always safe to call
    let now_mach = unsafe { mach_absolute_time() } as i128;
    // No underflow possible: we had two u64, the result of `a - b` will always fit in an i128
    let time_til_ticks = (mach_time as i128) - now_mach;
    let back_in_time = time_til_ticks < 0;
    let time_til = convert_mach_time_to_duration(time_til_ticks.unsigned_abs() as u64);

    if back_in_time {
        now.checked_sub(time_til).ok_or(TimeError::Overflow)
    } else {
        now.checked_add(time_til).ok_or(TimeError::Overflow)
    }
}

/// Convert a Mach absolute time to a [Duration].
pub(crate) fn convert_mach_time_to_duration(mach_time: u64) -> Duration {
    /// Storage for [struct@mach_timebase_info]
    ///
    /// NOTE: We pack the [struct@mach_timebase_info] structure into a [u64] to take advantage of atomics.
    static TIME_BASE_RAW_INFO: AtomicU64 = AtomicU64::new(0);

    let mut value = mti_from_u64(TIME_BASE_RAW_INFO.load(Ordering::Relaxed));

    // Similar to https://github.com/rust-lang/rust/blob/master/library/std/src/sys/unix/time.rs#L226-L253
    if value.denom == 0 || value.numer == 0 {
        // Safety: value needs to be a pointer initialized to a mach_timebase_info.
        unsafe { mach_timebase_info(&mut value) };

        TIME_BASE_RAW_INFO.store(u64_from_mti(value), Ordering::Relaxed)
    }

    let nanos = (mach_time * u64::from(value.numer)) / u64::from(value.denom);

    Duration::from_nanos(nanos)
}

/// [`u64`] to [`mach_timebase_info`][struct@mach_timebase_info]
fn mti_from_u64(raw_info: u64) -> mach_timebase_info {
    mach_timebase_info {
        numer: raw_info as u32,
        denom: (raw_info >> 32) as u32,
    }
}

/// [`mach_timebase_info`][struct@mach_timebase_info] to [`u64`]
fn u64_from_mti(info: mach_timebase_info) -> u64 {
    u64::from(info.denom) << 32 | u64::from(info.numer)
}

/// Convert a [`endpoint_sec_sys::timespec`] to a [`Duration`].
#[inline(always)]
pub(crate) fn convert_timespec_to_duration(t: endpoint_sec_sys::timespec) -> Duration {
    Duration::new(t.tv_sec as u64, t.tv_nsec as u32)
}

/// Converts an arbitrary slice of bytes to a [`CStr`] if it contains a nul byte or a [`CString`]
/// if it doesn't (and adds a nul byte at the end in this case).
///
/// It allocates only when there is no nul byte in the slice.
///
/// If the slice contains several nul bytes, it's cut at the first encountered.
#[inline(always)]
pub(crate) fn convert_byte_slice_to_cow_cstr(bytes: &[u8]) -> Cow<'_, CStr> {
    match bytes.iter().position(|x| *x == b'\0').map(|x| x.checked_add(1)) {
        Some(Some(one_past_nul)) => {
            // Safety: There is a nul in the string, it's not at `usize::MAX`
            Cow::Borrowed(unsafe { CStr::from_bytes_with_nul_unchecked(&bytes[..one_past_nul]) })
        },
        // Safety: There is a nul in the string, it's at `usize::MAX`
        Some(None) => Cow::Borrowed(unsafe { CStr::from_bytes_with_nul_unchecked(bytes) }),
        // We are forced to allocate in this case
        // Safety: there is no nul byte in the string
        None => Cow::Owned(unsafe { CString::from_vec_unchecked(bytes.into()) }),
    }
}
