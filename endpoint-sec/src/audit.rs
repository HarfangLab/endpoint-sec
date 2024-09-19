//! Expose a wrapper around [`audit_token_t`]: [`AuditToken`]

use std::fmt;

use endpoint_sec_sys::{
    au_asid_t, audit_token_t, audit_token_to_asid, audit_token_to_auid, audit_token_to_egid, audit_token_to_euid,
    audit_token_to_pid, audit_token_to_pidversion, audit_token_to_rgid, audit_token_to_ruid, gid_t, pid_t, uid_t,
};

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
    /// Get the [`AuditToken`] for the given pid, if it exists.
    ///
    /// Endpoint Security does not currently provide a way to get the audit tokens for already
    /// processes when first connecting a client, but it is relatively easy to list the PIDs of the
    /// current processes.
    ///
    /// ## Implementation details
    ///
    /// Currently this method is implemented following the method [described here][method], with
    /// calls to `task_name_for_pid` and `task_info(_, TASK_AUDIT_TOKEN, _, _)` but the first
    /// function is marked as *obsolete* in the header containing it in macOS's SDK.
    ///
    /// Other possibilities could be `task_for_pid()` or `task_inspect_for_pid()`. For now the
    /// current implementation is the most backward compatible. If you find a bug/need us to use a
    /// more recent method, please signal it.
    ///
    /// [method]: https://developer.apple.com/forums/thread/652363
    #[cfg(feature = "audit_token_from_pid")]
    pub fn from_pid(pid: pid_t) -> Option<Self> {
        use mach2::kern_return::kern_return_t;
        use mach2::vm_types::natural_t;

        /// Task port name
        #[allow(non_camel_case_types)]
        type mach_port_name_t = natural_t;

        extern "C" {
            // Absent in both libc and mach2
            fn task_name_for_pid(
                target_tport: mach_port_name_t,
                pid: pid_t,
                task_name: &mut mach_port_name_t,
            ) -> kern_return_t;
        }

        let mut task_name = Default::default();
        // Safety:
        // - `mach_task_self` will always succeed
        // - `task_name` is mutable and of the correct type so the reference is aligned and points
        //   to initialized memory
        // - result is checked below
        let res = unsafe { task_name_for_pid(libc::mach_task_self(), pid, &mut task_name) };
        if res != libc::KERN_SUCCESS {
            return None;
        }

        let mut audit_token = audit_token_t::default();
        // Capacity in bytes of the array in `audit_token`
        let mut cap = std::mem::size_of_val(&audit_token.val) as u32;
        // Safety:
        // - `task_name` is initialized
        // - `audit_token` is mutable and of the correct type so the reference is aligned and points
        //   to initialized memory, its type is in sync with `TASK_AUDIT_TOKEN` and `cap` is the
        //   capacity in bytes
        // - result is checked below
        let res = unsafe {
            libc::task_info(
                task_name,
                mach2::task_info::TASK_AUDIT_TOKEN,
                audit_token.val.as_mut_ptr().cast(),
                &mut cap,
            )
        };
        if res != libc::KERN_SUCCESS {
            return None;
        }

        Some(Self(audit_token))
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

#[cfg(test)]
#[cfg(feature = "audit_token_from_pid")]
mod test {
    use sysinfo::{Pid, PidExt, ProcessExt, ProcessRefreshKind, System, SystemExt};

    use super::*;

    #[test]
    fn audit_token_from_pid() {
        let raw_pid = std::process::id();

        let mut s = System::new();
        s.refresh_process_specifics(Pid::from_u32(raw_pid), ProcessRefreshKind::everything());

        let process = s.process(Pid::from_u32(raw_pid)).unwrap();

        let audit = AuditToken::from_pid(raw_pid as i32).unwrap();

        assert_eq!(process.user_id().map_or(0, |x| **x), audit.euid());
        assert_eq!(process.group_id().map_or(0, |x| *x), audit.egid());
        assert_eq!(process.pid().as_u32(), audit.pid() as u32);
    }
}
