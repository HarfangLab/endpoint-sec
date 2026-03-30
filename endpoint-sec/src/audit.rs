//! Expose a wrapper around [`audit_token_t`]: [`AuditToken`]

use std::fmt;
#[cfg(feature = "audit_token_from_pid")]
use std::mem;

use endpoint_sec_sys::{
    au_asid_t, audit_token_t, audit_token_to_asid, audit_token_to_auid, audit_token_to_egid, audit_token_to_euid,
    audit_token_to_pid, audit_token_to_pidversion, audit_token_to_rgid, audit_token_to_ruid, gid_t, pid_t, uid_t,
};
#[cfg(feature = "audit_token_from_pid")]
use libc::{KERN_SUCCESS, c_int};
#[cfg(feature = "audit_token_from_pid")]
use mach2::kern_return::kern_return_t;
#[cfg(feature = "audit_token_from_pid")]
use mach2::port::mach_port_name_t;
#[cfg(feature = "audit_token_from_pid")]
use mach2::task_info::TASK_AUDIT_TOKEN;

/// A wrapper around an [`audit_token_t`].
#[derive(Clone, Copy)]
#[doc(alias = "audit_token_t")]
#[repr(transparent)]
pub struct AuditToken(pub audit_token_t);

impl fmt::LowerHex for AuditToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for v in self.0.val {
            fmt::LowerHex::fmt(&v, f)?;
        }

        Ok(())
    }
}

impl fmt::UpperHex for AuditToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for v in self.0.val {
            fmt::UpperHex::fmt(&v, f)?;
        }

        Ok(())
    }
}

/// Endpoint Security wrappers and test helpers
impl AuditToken {
    /// Get the [`AuditToken`] for the given PID, if it exists.
    ///
    /// Endpoint Security does not currently provide a way to get the audit tokens of processes
    /// already existing when first connecting a client. However, it is relatively easy to list
    /// the PIDs of the current processes. This function therefore enables to bridge this gap.
    ///
    /// Errors from the underlying system calls are returned directly. Although it is almost
    /// certain that only the catch-all `KERN_FAILURE` (5) will ever be observed in practice, this
    /// should still be useful in order to emphasize that the unexpected case should be accounted
    /// for instead of just discarded, for example to then log.
    ///
    /// ## Implementation details
    ///
    /// Currently this method is implemented following the method [described here][method], with
    /// calls to `task_name_for_pid` and `task_info(_, TASK_AUDIT_TOKEN, _, _)` but the first
    /// function is marked as *obsolete* in the header containing it in macOS's SDK.
    ///
    /// Other possibilities could be `task_for_pid()` or `task_inspect_for_pid()`. For now, the
    /// current implementation is the most backwards and forwards compatible considering
    /// `task_for_pid()` now concretely requires SIP to be disabled, which thus makes it pretty
    /// much unusable. If you find a bug/need us to use a more recent method, please signal it.
    ///
    /// [method]: https://developer.apple.com/forums/thread/652363
    #[cfg(feature = "audit_token_from_pid")]
    pub fn from_pid(pid: pid_t) -> Result<Self, kern_return_t> {
        Ok(Self(mach_task_audit_token(mach_task_name(pid)?)?))
    }

    /// Raw underlying audit token.
    #[inline]
    pub fn raw_token(&self) -> &audit_token_t {
        &self.0
    }

    /// The audit user ID.
    ///
    /// **NOTE**: Used to identify Mach tasks and senders of Mach messages as subjects of the audit system.
    #[inline(always)]
    pub fn auid(&self) -> uid_t {
        // Safety: The audit_token_t is owned by self.
        unsafe { audit_token_to_auid(self.0) }
    }

    /// The effective user ID.
    ///
    /// **NOTE**: Used to identify Mach tasks and senders of Mach messages as subjects of the audit system.
    #[inline(always)]
    pub fn euid(&self) -> uid_t {
        // Safety: The audit_token_t is owned by self.
        unsafe { audit_token_to_euid(self.0) }
    }

    /// The effective group ID.
    ///
    /// **NOTE**: Used to identify Mach tasks and senders of Mach messages as subjects of the audit system.
    #[inline(always)]
    pub fn egid(&self) -> gid_t {
        // Safety: The audit_token_t is owned by self.
        unsafe { audit_token_to_egid(self.0) }
    }

    /// The real user ID.
    ///
    /// **NOTE**: Used to identify Mach tasks and senders of Mach messages as subjects of the audit system.
    #[inline(always)]
    pub fn ruid(&self) -> uid_t {
        // Safety: The audit_token_t is owned by self.
        unsafe { audit_token_to_ruid(self.0) }
    }

    /// The real group ID.
    ///
    /// **NOTE**: Used to identify Mach tasks and senders of Mach messages as subjects of the audit system.
    #[inline(always)]
    pub fn rgid(&self) -> gid_t {
        // Safety: The audit_token_t is owned by self.
        unsafe { audit_token_to_rgid(self.0) }
    }

    /// The process ID.
    ///
    /// **NOTE**: Used to identify Mach tasks and senders of Mach messages as subjects of the audit system.
    #[inline(always)]
    pub fn pid(&self) -> pid_t {
        // Safety: The audit_token_t is owned by self.
        unsafe { audit_token_to_pid(self.0) }
    }

    /// The audit session ID.
    ///
    /// **NOTE**: Used to identify Mach tasks and senders of Mach messages as subjects of the audit system.
    #[inline(always)]
    pub fn asid(&self) -> au_asid_t {
        // Safety: The audit_token_t is owned by self.
        unsafe { audit_token_to_asid(self.0) }
    }

    /// The process ID version.
    ///
    /// **NOTE**: Used to identify Mach tasks and senders of Mach messages as subjects of the audit system.
    #[inline(always)]
    pub fn pidversion(&self) -> i32 {
        // Safety: The audit_token_t is owned by self.
        unsafe { audit_token_to_pidversion(self.0) }
    }
}

/// Crate-private methods
impl AuditToken {
    /// Create a new [`AuditToken`] from [`audit_token_t`].
    #[inline(always)]
    pub(crate) fn new(token: audit_token_t) -> Self {
        AuditToken(token)
    }

    /// Allow to grab a reference out of the stored token.
    #[inline(always)]
    pub(crate) fn get_raw_ref(&self) -> &audit_token_t {
        &self.0
    }
}

#[cfg(feature = "static_assertions")]
static_assertions::assert_impl_all!(AuditToken: Send);

impl_debug_eq_hash_with_functions!(
    AuditToken;
    auid,
    euid,
    egid,
    ruid,
    rgid,
    pid,
    asid,
    pidversion,
);

/// Safe wrapper around [`task_name_for_pid`].
#[cfg(feature = "audit_token_from_pid")]
fn mach_task_name(pid: pid_t) -> Result<mach_port_name_t, kern_return_t> {
    let mut task_name = mach_port_name_t::default();

    // SAFETY:
    //  * `mach_task_self` is always safe to call: resolves a static variable;
    //  * `task_name` is mutable and of the correct type so the reference is
    //    aligned and points to initialized memory;
    //  * errors are checked for below;
    let res = unsafe { task_name_for_pid(mach2::traps::mach_task_self(), pid, &mut task_name) };

    if res == KERN_SUCCESS { Ok(task_name) } else { Err(res) }
}

/// Safe wrapper around [`libc::task_info`] specialized for [`TASK_AUDIT_TOKEN`].
#[cfg(feature = "audit_token_from_pid")]
fn mach_task_audit_token(task_name: mach_port_name_t) -> Result<audit_token_t, kern_return_t> {
    let mut audit_token = audit_token_t::default();
    let mut audit_token_size = mem::size_of_val(&audit_token.val) as u32;

    // SAFETY:
    //  * `task_name` is initialized;
    //  * `audit_token` is mutable and of the correct type so the reference
    //    is aligned and points to initialized memory, its type is in sync
    //    with `TASK_AUDIT_TOKEN` and `audit_token_size` is its size in bytes;
    //  * errors are checked for below;
    let res = unsafe {
        libc::task_info(
            task_name,
            TASK_AUDIT_TOKEN,
            audit_token.val.as_mut_ptr().cast(),
            &mut audit_token_size,
        )
    };

    if res == KERN_SUCCESS { Ok(audit_token) } else { Err(res) }
}

#[cfg(feature = "audit_token_from_pid")]
unsafe extern "C" {
    // TODO: Replace with the one from `mach2::traps` when
    // https://github.com/JohnTitor/mach2/pull/71 is merged and released.
    fn task_name_for_pid(target_tport: mach_port_name_t, pid: c_int, tn: *mut mach_port_name_t) -> kern_return_t;
}

#[cfg(test)]
#[cfg(feature = "audit_token_from_pid")]
mod test {
    use sysinfo::{PidExt, ProcessExt, ProcessRefreshKind, RefreshKind, System, SystemExt};

    use super::*;

    #[test]
    fn audit_token_from_pid() {
        let s = System::new_with_specifics(RefreshKind::new().with_processes(ProcessRefreshKind::everything()));

        for (pid, process) in s.processes() {
            let audit_token = AuditToken::from_pid(pid.as_u32() as pid_t).unwrap();

            assert_eq!(process.user_id().map_or(0, |x| **x), audit_token.euid());
            assert_eq!(process.group_id().map_or(0, |x| *x), audit_token.egid());
            assert_eq!(process.pid().as_u32(), audit_token.pid() as u32);
        }
    }
}
