//! Definitions of Endpoint Security Message.

use std::ffi::OsStr;
use std::ptr::NonNull;
#[cfg(feature = "macos_10_15_4")]
use std::time::Duration;
use std::time::{Instant, SystemTime};

use endpoint_sec_sys::*;

use crate::{utils, Action, ActionResult, AuditToken, Event};

/// A message from Endpoint Security.
///
/// Be careful with `AUTH` messages, they must be responded to before their deadline (see
/// [`Message::deadline()`]) else Endpoint Security may kill your client as it slows the OS too much.
///
/// ## Implementation details (macOS 11+)
///
/// Behind the scene, [`es_message_t`] is a reference-counted object, which means `Clone`-ing a
/// `Message` won't actually create a new message, but merely increment its refcount and return a
/// new handle to that object. This is very cheap and can be done without much performance overhead.
///
/// ## Implementation details (macOS 10.15.x)
///
/// Dropping a `Message` while inside a handler may cause your app to **crash**. We copy the message
/// before handing it over for your usage but that may not be enough, so be thorough in testing.
///
/// See <https://developer.apple.com/documentation/endpointsecurity/3366178-es_free_message>.
#[doc(alias = "es_message_t")]
pub struct Message(NonNull<es_message_t>);

impl Message {
    /// Create a new [`Message`] from a raw pointer.
    ///
    /// # Safety
    ///
    /// `msg` must point to a valid live [`es_message_t`] object.
    ///
    /// # Details
    ///
    /// On macOS 11.0+, with the feature `"macos_11_0_0"` (or more) active, this uses
    #[cfg_attr(
        feature = "macos_11_0_0",
        doc = "[`es_retain_message()`], which is basically an `Arc::clone()`."
    )]
    #[cfg_attr(
        not(feature = "macos_11_0_0"),
        doc = "`es_retain_message()`, which is basically an `Arc::clone()`."
    )]
    ///
    /// On macOS 10.15.x, this calls [`es_copy_message()`].
    #[inline(always)]
    pub unsafe fn from_raw(msg: NonNull<es_message_t>) -> Self {
        let msg = versioned_call!(if cfg!(feature = "macos_11_0_0") && version >= (11, 0, 0) {
            // Safety: the caller must guarantee that `msg` is a valid live es_message_t object.
            unsafe { es_retain_message(msg.as_ref()) };
            msg
        } else {
            // Safety: the caller must guarantee that `msg` is a valid live es_message_t object.
            let msg = unsafe { es_copy_message(msg.as_ref()) };
            NonNull::new(msg).expect("es_copy_message returned NULL")
        });
        Self(msg)
    }

    /// Allow to grab a reference out of the stored pointer.
    ///
    /// This allows to reduce the boilerplate for all other methods.
    #[inline(always)]
    pub(crate) fn get_raw_ref(&self) -> &es_message_t {
        // Safety: inner message is a valid live object by construction.
        unsafe { self.0.as_ref() }
    }

    /// Version of the Endpoint Security message.
    #[inline(always)]
    pub fn version(&self) -> u32 {
        self.get_raw_ref().version
    }

    /// Time at which the event was generated.
    ///
    /// See also [`Self::time()`].
    ///
    /// Ref: <https://developer.apple.com/documentation/kernel/timespec>
    #[inline(always)]
    pub fn raw_time(&self) -> endpoint_sec_sys::timespec {
        self.get_raw_ref().time
    }

    /// Time at which the event was generated, as a [`SystemTime`].
    ///
    /// See also [`Self::raw_time()`].
    #[inline(always)]
    pub fn time(&self) -> SystemTime {
        let dur = utils::convert_timespec_to_duration(self.raw_time());
        SystemTime::UNIX_EPOCH + dur
    }

    /// Time at which the event was generated, as Mach absolute time.
    ///
    /// This is basically a duration since the machine booted up.
    ///
    /// See also [`Self::mach_time()`].
    ///
    /// Ref: <https://developer.apple.com/documentation/kernel/1462446-mach_absolute_time>
    #[inline(always)]
    pub fn raw_mach_time(&self) -> u64 {
        self.get_raw_ref().mach_time
    }

    /// Time at which the event was generated, as an [`Instant`].
    ///
    /// This is basically a duration since the machine booted up.
    ///
    /// See also [`Self::raw_mach_time()`].
    #[inline(always)]
    pub fn mach_time(&self) -> Result<Instant, TimeError> {
        utils::convert_mach_time_to_instant(self.raw_mach_time())
    }

    /// Time before which an AUTH event **must** be responded to, as Mach absolute time.
    ///
    /// **Warning**: The client needs to respond to auth events prior to the `deadline` otherwise
    /// the application will be killed.
    ///
    /// See also [`Self::deadline()`].
    ///
    /// Ref: <https://developer.apple.com/documentation/kernel/1462446-mach_absolute_time>
    #[inline(always)]
    pub fn raw_deadline(&self) -> u64 {
        self.get_raw_ref().deadline
    }

    /// Time before which an AUTH event **must** be responded to, as an [`Instant`].
    ///
    /// **Warning**: The client needs to respond to auth events prior to the `deadline` otherwise
    /// the application will be killed.
    ///
    /// See also [`Self::raw_deadline()`].
    #[inline(always)]
    pub fn deadline(&self) -> Result<Instant, TimeError> {
        utils::convert_mach_time_to_instant(self.raw_deadline())
    }

    /// Describes the process that took the action.
    #[inline(always)]
    pub fn process(&self) -> Process<'_> {
        Process::new(
            // Safety: 'a tied to self, object obtained through ES
            unsafe { self.get_raw_ref().process() },
            self.version(),
        )
    }

    /// Per client event sequence number on version 2 and later, otherwise None.
    #[cfg(feature = "macos_10_15_4")]
    #[inline(always)]
    pub fn seq_num(&self) -> Option<u64> {
        if self.version() >= 2 {
            Some(self.get_raw_ref().seq_num)
        } else {
            None
        }
    }

    /// Indicates if the action field is an auth or notify action.
    #[inline(always)]
    pub fn action_type(&self) -> es_action_type_t {
        self.get_raw_ref().action_type
    }

    /// For auth events, contains the opaque auth ID that must be supplied when responding to the
    /// event. For notify events, describes the result of the action.
    #[inline(always)]
    pub fn action(&self) -> Option<Action> {
        match self.action_type() {
            // Safety: we just checked the `action_type` member
            es_action_type_t::ES_ACTION_TYPE_AUTH => Some(Action::Auth(unsafe { self.get_raw_ref().action.auth })),
            // Safety: we just checked the `action_type` member and the content of `notify` is
            // checked in the `ActionResult::from_raw` call
            es_action_type_t::ES_ACTION_TYPE_NOTIFY => Some(Action::Notify(ActionResult::from_raw(unsafe {
                self.get_raw_ref().action.notify
            })?)),
            _ => None,
        }
    }

    /// Indicates which event struct is defined in the event union.
    #[inline(always)]
    pub fn event_type(&self) -> es_event_type_t {
        self.get_raw_ref().event_type
    }

    /// Event associated to this message.
    #[inline(always)]
    pub fn event(&self) -> Option<Event<'_>> {
        // Safety: all arguments are from the current message instance.
        unsafe { Event::from_raw_parts(self.event_type(), &self.get_raw_ref().event, self.version()) }
    }

    /// Thread associated to this message (if present) on version 4 and later, otherwise None.
    #[cfg(feature = "macos_11_0_0")]
    #[inline(always)]
    pub fn thread(&self) -> Option<Thread<'_>> {
        if self.version() >= 4 {
            // Safety: Safe as Thread cannot outlive self and meet all requirements of a reference.
            let thread_res = unsafe { self.get_raw_ref().thread.as_ref() };

            thread_res.map(Thread::new)
        } else {
            None
        }
    }

    /// Per client global sequence number on version 4 and later, otherwise None.
    #[cfg(feature = "macos_11_0_0")]
    #[inline(always)]
    pub fn global_seq_num(&self) -> Option<u64> {
        if self.version() >= 4 {
            Some(self.get_raw_ref().global_seq_num)
        } else {
            None
        }
    }
}

impl Clone for Message {
    #[inline(always)]
    fn clone(&self) -> Self {
        // Safety: we already have a valid Message, increasing the reference count is ok
        // on macOS < 11.0, this will call `es_copy_message` instead, which is semantically the same.
        unsafe { Self::from_raw(self.0) }
    }
}

impl Drop for Message {
    #[inline(always)]
    fn drop(&mut self) {
        versioned_call!(if cfg!(feature = "macos_11_0_0") && version >= (11, 0, 0) {
            // Safety: we are dropping the Message so it's safe to release it.
            unsafe { es_release_message(self.0.as_ref()) };
        } else {
            // Safety: we are dropping the Message so it's safe to free it.
            unsafe { es_free_message(self.0.as_ref()) };
        })
    }
}

/// Safety: Message is safe to send across threads - it does not contain any interior mutability, nor depend on current thread state.
unsafe impl Send for Message {}
/// Safety: Message is safe to share between threads - it does not contain any interior mutability.
unsafe impl Sync for Message {}

impl_debug_eq_hash_with_functions!(
    Message;
    action_type,
    action,
    deadline,
    event,
    event_type,
    #[cfg(feature = "macos_11_0_0")]
    global_seq_num,
    mach_time,
    process,
    #[cfg(feature = "macos_10_15_4")]
    seq_num,
    #[cfg(feature = "macos_11_0_0")]
    thread,
    time,
    version,
);

/// Error produced when trying to access [`Message::deadline()`] or equivalent functions because
/// computing the `[`Instant`] overflowed.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum TimeError {
    /// Computing the deadline overflowed
    Overflow,
}

impl std::error::Error for TimeError {}

impl std::fmt::Display for TimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Overflow => "Computing deadline overflowed",
        })
    }
}

/// Information related to a thread.
#[cfg(feature = "macos_11_0_0")]
pub struct Thread<'a>(&'a es_thread_t);

#[cfg(feature = "macos_11_0_0")]
impl<'a> Thread<'a> {
    /// Create a new [`Thread`] instance.
    #[inline(always)]
    pub const fn new(raw: &'a es_thread_t) -> Self {
        Thread(raw)
    }

    /// The unique thread ID of the thread.
    #[inline(always)]
    pub fn thread_id(&self) -> u64 {
        self.0.thread_id
    }
}

#[cfg(feature = "macos_11_0_0")]
// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for Thread<'_> {}

#[cfg(feature = "macos_11_0_0")]
impl_debug_eq_hash_with_functions!(Thread<'a>; thread_id);

/// Provides the stat information and path to a file that relates to a security event.
pub struct File<'a>(&'a es_file_t);

impl<'a> File<'a> {
    /// Create a new [`File`] instance.
    #[inline(always)]
    pub const fn new(raw: &'a es_file_t) -> Self {
        File(raw)
    }

    /// The path to the file.
    #[inline(always)]
    pub fn path(&self) -> &'a OsStr {
        // Safety: 'a tied to self, object obtained through ES
        unsafe { self.0.path.as_os_str() }
    }

    /// Returns true to indicate if the path was truncated.
    #[inline(always)]
    pub fn path_truncated(&self) -> bool {
        self.0.path_truncated
    }

    /// The [`stat`][struct@stat] to the file.
    #[inline(always)]
    pub fn stat(&self) -> &'a stat {
        &self.0.stat
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for File<'_> {}

impl_debug_eq_hash_with_functions!(File<'a>; path, path_truncated, stat);

/// Information related to a process.
pub struct Process<'a> {
    /// The raw reference.
    raw: &'a es_process_t,

    /// The version of the message.
    version: u32,
}

impl<'a> Process<'a> {
    /// Create a new [`Process`] instance.
    #[inline(always)]
    pub const fn new(raw: &'a es_process_t, version: u32) -> Self {
        Process { raw, version }
    }

    /// Audit token of the process.
    #[inline(always)]
    pub fn audit_token(&self) -> AuditToken {
        AuditToken::new(self.raw.audit_token)
    }

    /// Parent pid of the process.
    ///
    #[cfg_attr(
        feature = "macos_11_0_0",
        doc = "**Warning**: It is recommended to instead use [`Self::parent_audit_token()`] when available."
    )]
    #[cfg_attr(
        not(feature = "macos_11_0_0"),
        doc = "**Warning**: It is recommended to instead use `Self::parent_audit_token()` when available."
    )]
    #[inline(always)]
    pub fn ppid(&self) -> pid_t {
        self.raw.ppid
    }

    /// Original ppid of the process.
    #[inline(always)]
    pub fn original_ppid(&self) -> pid_t {
        self.raw.original_ppid
    }

    /// Process group id the process belongs to.
    #[inline(always)]
    pub fn group_id(&self) -> pid_t {
        self.raw.group_id
    }

    /// Process session id the process belongs to.
    #[inline(always)]
    pub fn session_id(&self) -> pid_t {
        self.raw.session_id
    }

    /// Code signing flags of the process.
    #[inline(always)]
    pub fn codesigning_flags(&self) -> u32 {
        self.raw.codesigning_flags
    }

    /// Indicates whether the process is a platform binary.
    ///
    /// **Note**: A "platform binary" is a binary signed with Apple certificates.
    ///
    /// ## Usage of `is_platform_binary` with `Message`s and `EventExec`s
    ///
    /// If your application is looking to allow/deny [`AuthExec`][crate::Event::AuthExec]
    /// events, be sure to check [`EventExec::target()`][crate::EventExec::target], **not**
    /// [`Message::process()`], else you will get the wrong result, especially since pretty much
    /// all processes are lauched through `xpcproxy`, a platform binary.
    #[inline(always)]
    pub fn is_platform_binary(&self) -> bool {
        self.raw.is_platform_binary
    }

    /// Indicates this process has the Endpoint Security entitlement.
    #[inline(always)]
    pub fn is_es_client(&self) -> bool {
        self.raw.is_es_client
    }

    /// Code directory hash of the code signature associated with this process.
    #[inline(always)]
    pub fn cdhash(&self) -> [u8; 20] {
        self.raw.cdhash
    }

    /// Signing id of the code signature associated with this process.
    #[inline(always)]
    pub fn signing_id(&self) -> &'a OsStr {
        // Safety: 'a tied to self, object obtained through ES
        unsafe { self.raw.signing_id.as_os_str() }
    }

    /// Team id of the code signature associated with this process.
    #[inline(always)]
    pub fn team_id(&self) -> &'a OsStr {
        // Safety: 'a tied to self, object obtained through ES
        unsafe { self.raw.team_id.as_os_str() }
    }

    /// Executable file that is executing in this process.
    #[inline(always)]
    pub fn executable(&self) -> File<'a> {
        // Safety: 'a tied to self, object obtained through ES
        File::new(unsafe { self.raw.executable() })
    }

    /// TTY associated to this process (if present) on version 2 and later, otherwise None.
    #[cfg(feature = "macos_10_15_1")]
    #[inline(always)]
    pub fn tty(&self) -> Option<File<'a>> {
        if self.version >= 2 {
            // Safety: Safe as File cannot outlive self and meet all requirements of a reference.
            unsafe { self.raw.tty.as_ref() }.map(File::new)
        } else {
            None
        }
    }

    /// Process start time on version 3 and later, otherwise None.
    #[cfg(feature = "macos_10_15_4")]
    #[inline(always)]
    pub fn start_time(&self) -> Option<SystemTime> {
        if self.version >= 3 {
            // timeval is the elapsed time since unix epoch, as such it shouldn't be negative.
            let timestamp = Duration::from_secs(self.raw.start_time.tv_sec as u64)
                + Duration::from_micros(self.raw.start_time.tv_usec as u64);

            if let Some(system_time) = SystemTime::UNIX_EPOCH.checked_add(timestamp) {
                Some(system_time)
            } else {
                // In case of overflow, default to epoch.
                Some(SystemTime::UNIX_EPOCH)
            }
        } else {
            None
        }
    }

    /// Audit token of the process responsible for this process on version 4 and later, if any.
    ///
    /// **Warning**: It may be the process itself in case there is no responsible process or the
    /// responsible process has already exited.
    #[cfg(feature = "macos_11_0_0")]
    #[inline(always)]
    pub fn responsible_audit_token(&self) -> Option<AuditToken> {
        if self.version >= 4 {
            Some(AuditToken::new(self.raw.responsible_audit_token))
        } else {
            None
        }
    }

    /// Audit token of the parent process on version 4 and later, otherwise None.
    #[cfg(feature = "macos_11_0_0")]
    #[inline(always)]
    pub fn parent_audit_token(&self) -> Option<AuditToken> {
        if self.version >= 4 {
            Some(AuditToken::new(self.raw.parent_audit_token))
        } else {
            None
        }
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for Process<'_> {}

impl_debug_eq_hash_with_functions!(
    Process<'a> with version;
    audit_token,
    cdhash,
    codesigning_flags,
    executable,
    group_id,
    is_es_client,
    is_platform_binary,
    original_ppid,
    #[cfg(feature = "macos_11_0_0")]
    parent_audit_token,
    ppid,
    #[cfg(feature = "macos_11_0_0")]
    responsible_audit_token,
    session_id,
    signing_id,
    #[cfg(feature = "macos_10_15_4")]
    start_time,
    team_id,
    #[cfg(feature = "macos_10_15_1")]
    tty,
);

/// Describes machine-specific thread state as used by `thread_create_running()` and other Mach API functions.
#[cfg(feature = "macos_11_0_0")]
pub struct ThreadState<'a>(&'a es_thread_state_t);

#[cfg(feature = "macos_11_0_0")]
impl<'a> ThreadState<'a> {
    /// Create a new [`ThreadState`] instance.
    #[inline(always)]
    pub const fn new(raw: &'a es_thread_state_t) -> Self {
        ThreadState(raw)
    }

    /// Indicates the representation of the machine-specific thread state.
    #[inline(always)]
    pub fn flavor(&self) -> i32 {
        self.0.flavor
    }

    /// The machine-specific thread state, equivalent to `thread_state_t` in Mach APIs.
    #[inline(always)]
    pub fn state(&self) -> &'a [u8] {
        // Safety: 'a tied to self, object obtained through ES
        unsafe { self.0.state.as_slice() }
    }
}

#[cfg(feature = "macos_11_0_0")]
// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for ThreadState<'_> {}

#[cfg(feature = "macos_11_0_0")]
impl_debug_eq_hash_with_functions!(ThreadState<'a>; flavor, state);
