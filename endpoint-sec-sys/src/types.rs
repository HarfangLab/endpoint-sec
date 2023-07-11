//! Corresponding header: `EndpointSecurity/ESTypes.h`

// Types and methods should be added in the same order as they are in the original header to make
// maintenance easier.

use core::fmt;
use core::hash::Hash;
use core::slice::from_raw_parts;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;

pub use libc::{c_char, size_t};

use super::audit_token_t;

/// Unique ID for an event
#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct es_event_id_t {
    _reserved: [u8; 32],
}

// Make the debug representation an hex string to make it shorter and clearer when debugging
impl fmt::Debug for es_event_id_t {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("es_event_id_t").field(&format!("{:#X}", self)).finish()
    }
}

impl fmt::LowerHex for es_event_id_t {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for v in self._reserved {
            fmt::LowerHex::fmt(&v, f)?;
        }

        Ok(())
    }
}

impl fmt::UpperHex for es_event_id_t {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for v in self._reserved {
            fmt::UpperHex::fmt(&v, f)?;
        }

        Ok(())
    }
}

ffi_wrap_enum!(
    /// Type of action to take after receiving a message
    es_action_type_t(u32);

    == MACOS_10_15_0;
    /// Event needs a response before its deadline
    ES_ACTION_TYPE_AUTH = 0,
    --
    /// Event needs no response, it is informative only
    ES_ACTION_TYPE_NOTIFY = 1,
);

ffi_wrap_enum!(
    /// Whether an ACL is being set or cleared
    ///
    /// See [`es_event_setacl_t`][super::es_event_setacl_t]
    es_set_or_clear_t(u32);

    == MACOS_10_15_0;
    /// ACL is being set
    ES_SET = 0,
    --
    /// ACL is being cleared
    ES_CLEAR = 1,
);

ffi_wrap_enum!(
    /// This enum describes the type of [`es_event_proc_check_t`][crate::es_event_proc_check_t]
    /// events that are currently used.
    ///
    /// `ES_PROC_CHECK_TYPE_KERNMSGBUF`, `ES_PROC_CHECK_TYPE_TERMINATE` and
    /// `ES_PROC_CHECK_TYPE_UDATA_INFO` are deprecated and no `proc_check` messages will be
    /// generated for the corresponding `proc_info` call numbers.
    ///
    /// The terminate callnum is covered by the signal event.
    es_proc_check_type_t(u32);

    == MACOS_10_15_0;
    ES_PROC_CHECK_TYPE_LISTPIDS = 0x1,
    ES_PROC_CHECK_TYPE_PIDINFO = 0x2,
    ES_PROC_CHECK_TYPE_PIDFDINFO = 0x3,
    /// Deprecated, not generated anymore (since when ?)
    ES_PROC_CHECK_TYPE_KERNMSGBUF = 0x4,
    ES_PROC_CHECK_TYPE_SETCONTROL = 0x5,
    ES_PROC_CHECK_TYPE_PIDFILEPORTINFO = 0x6,
    /// Deprecated, not generated anymore (since when ?)
    ES_PROC_CHECK_TYPE_TERMINATE = 0x7,
    ES_PROC_CHECK_TYPE_DIRTYCONTROL = 0x8,
    ES_PROC_CHECK_TYPE_PIDRUSAGE = 0x9,
    --
    /// Deprecated, not generated anymore (since when ?)
    ES_PROC_CHECK_TYPE_UDATA_INFO = 0xe,
);

#[cfg(feature = "macos_13_0_0")]
ffi_wrap_enum!(
    /// This enum describes the types of authentications that
    /// [`ES_EVENT_TYPE_NOTIFY_AUTHENTICATION`][es_event_type_t] can describe.
    es_authentication_type_t(u32);

    == LAST;
    // `ES_AUTHENTICATION_TYPE_LAST` is not a valid type of authentication but is a convenience
    // value to operate on the range of defined authentication types.
    ES_AUTHENTICATION_TYPE_LAST,

    == MACOS_13_0_0;
    ES_AUTHENTICATION_TYPE_OD = 0,
    ES_AUTHENTICATION_TYPE_TOUCHID = 1,
    ES_AUTHENTICATION_TYPE_TOKEN = 2,
    --
    ES_AUTHENTICATION_TYPE_AUTO_UNLOCK = 3,
);

ffi_wrap_enum!(
    /// The valid event types recognized by Endpoint Security.
    ///
    /// When a program subscribes to and receives an `AUTH`-related event, it must respond with an
    /// appropriate result indicating whether or not the operation should be allowed to continue.
    ///
    /// The valid API options are:
    ///
    ///  - [`es_respond_auth_result`][super::es_respond_auth_result]
    ///  - [`es_respond_flags_result`][super::es_respond_flags_result]
    ///
    /// Currently, only [`Self::ES_EVENT_TYPE_AUTH_OPEN`] must use `es_respond_flags_result`. All
    /// other `AUTH` events must use `es_respond_auth_result`.
    es_event_type_t(u32);

    == LAST;
    ES_EVENT_TYPE_LAST,

    == MACOS_10_15_0;
    ES_EVENT_TYPE_AUTH_EXEC = 0,
    ES_EVENT_TYPE_AUTH_OPEN = 1,
    ES_EVENT_TYPE_AUTH_KEXTLOAD = 2,
    ES_EVENT_TYPE_AUTH_MMAP = 3,
    ES_EVENT_TYPE_AUTH_MPROTECT = 4,
    ES_EVENT_TYPE_AUTH_MOUNT = 5,
    ES_EVENT_TYPE_AUTH_RENAME = 6,
    ES_EVENT_TYPE_AUTH_SIGNAL = 7,
    ES_EVENT_TYPE_AUTH_UNLINK = 8,
    ES_EVENT_TYPE_NOTIFY_EXEC = 9,
    ES_EVENT_TYPE_NOTIFY_OPEN = 10,
    ES_EVENT_TYPE_NOTIFY_FORK = 11,
    ES_EVENT_TYPE_NOTIFY_CLOSE = 12,
    ES_EVENT_TYPE_NOTIFY_CREATE = 13,
    ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA = 14,
    ES_EVENT_TYPE_NOTIFY_EXIT = 15,
    ES_EVENT_TYPE_NOTIFY_GET_TASK = 16,
    ES_EVENT_TYPE_NOTIFY_KEXTLOAD = 17,
    ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD = 18,
    ES_EVENT_TYPE_NOTIFY_LINK = 19,
    ES_EVENT_TYPE_NOTIFY_MMAP = 20,
    ES_EVENT_TYPE_NOTIFY_MPROTECT = 21,
    ES_EVENT_TYPE_NOTIFY_MOUNT = 22,
    ES_EVENT_TYPE_NOTIFY_UNMOUNT = 23,
    ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN = 24,
    ES_EVENT_TYPE_NOTIFY_RENAME = 25,
    ES_EVENT_TYPE_NOTIFY_SETATTRLIST = 26,
    ES_EVENT_TYPE_NOTIFY_SETEXTATTR = 27,
    ES_EVENT_TYPE_NOTIFY_SETFLAGS = 28,
    ES_EVENT_TYPE_NOTIFY_SETMODE = 29,
    ES_EVENT_TYPE_NOTIFY_SETOWNER = 30,
    ES_EVENT_TYPE_NOTIFY_SIGNAL = 31,
    ES_EVENT_TYPE_NOTIFY_UNLINK = 32,
    ES_EVENT_TYPE_NOTIFY_WRITE = 33,
    ES_EVENT_TYPE_AUTH_FILE_PROVIDER_MATERIALIZE = 34,
    ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_MATERIALIZE = 35,
    ES_EVENT_TYPE_AUTH_FILE_PROVIDER_UPDATE = 36,
    ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_UPDATE = 37,
    ES_EVENT_TYPE_AUTH_READLINK = 38,
    ES_EVENT_TYPE_NOTIFY_READLINK = 39,
    ES_EVENT_TYPE_AUTH_TRUNCATE = 40,
    ES_EVENT_TYPE_NOTIFY_TRUNCATE = 41,
    ES_EVENT_TYPE_AUTH_LINK = 42,
    ES_EVENT_TYPE_NOTIFY_LOOKUP = 43,
    ES_EVENT_TYPE_AUTH_CREATE = 44,
    ES_EVENT_TYPE_AUTH_SETATTRLIST = 45,
    ES_EVENT_TYPE_AUTH_SETEXTATTR = 46,
    ES_EVENT_TYPE_AUTH_SETFLAGS = 47,
    ES_EVENT_TYPE_AUTH_SETMODE = 48,
    --
    ES_EVENT_TYPE_AUTH_SETOWNER = 49,

    == MACOS_10_15_1;
    ES_EVENT_TYPE_AUTH_CHDIR = 50,
    ES_EVENT_TYPE_NOTIFY_CHDIR = 51,
    ES_EVENT_TYPE_AUTH_GETATTRLIST = 52,
    ES_EVENT_TYPE_NOTIFY_GETATTRLIST = 53,
    ES_EVENT_TYPE_NOTIFY_STAT = 54,
    ES_EVENT_TYPE_NOTIFY_ACCESS = 55,
    ES_EVENT_TYPE_AUTH_CHROOT = 56,
    ES_EVENT_TYPE_NOTIFY_CHROOT = 57,
    ES_EVENT_TYPE_AUTH_UTIMES = 58,
    ES_EVENT_TYPE_NOTIFY_UTIMES = 59,
    ES_EVENT_TYPE_AUTH_CLONE = 60,
    ES_EVENT_TYPE_NOTIFY_CLONE = 61,
    ES_EVENT_TYPE_NOTIFY_FCNTL = 62,
    ES_EVENT_TYPE_AUTH_GETEXTATTR = 63,
    ES_EVENT_TYPE_NOTIFY_GETEXTATTR = 64,
    ES_EVENT_TYPE_AUTH_LISTEXTATTR = 65,
    ES_EVENT_TYPE_NOTIFY_LISTEXTATTR = 66,
    ES_EVENT_TYPE_AUTH_READDIR = 67,
    ES_EVENT_TYPE_NOTIFY_READDIR = 68,
    ES_EVENT_TYPE_AUTH_DELETEEXTATTR = 69,
    ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR = 70,
    ES_EVENT_TYPE_AUTH_FSGETPATH = 71,
    ES_EVENT_TYPE_NOTIFY_FSGETPATH = 72,
    ES_EVENT_TYPE_NOTIFY_DUP = 73,
    ES_EVENT_TYPE_AUTH_SETTIME = 74,
    ES_EVENT_TYPE_NOTIFY_SETTIME = 75,
    ES_EVENT_TYPE_NOTIFY_UIPC_BIND = 76,
    ES_EVENT_TYPE_AUTH_UIPC_BIND = 77,
    ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT = 78,
    ES_EVENT_TYPE_AUTH_UIPC_CONNECT = 79,
    ES_EVENT_TYPE_AUTH_EXCHANGEDATA = 80,
    ES_EVENT_TYPE_AUTH_SETACL = 81,
    --
    ES_EVENT_TYPE_NOTIFY_SETACL = 82,

    == MACOS_10_15_4;
    ES_EVENT_TYPE_NOTIFY_PTY_GRANT = 83,
    ES_EVENT_TYPE_NOTIFY_PTY_CLOSE = 84,
    ES_EVENT_TYPE_AUTH_PROC_CHECK = 85,
    ES_EVENT_TYPE_NOTIFY_PROC_CHECK = 86,
    --
    ES_EVENT_TYPE_AUTH_GET_TASK = 87,

    == MACOS_11_0_0;
    ES_EVENT_TYPE_AUTH_SEARCHFS = 88,
    ES_EVENT_TYPE_NOTIFY_SEARCHFS = 89,
    ES_EVENT_TYPE_AUTH_FCNTL = 90,
    ES_EVENT_TYPE_AUTH_IOKIT_OPEN = 91,
    ES_EVENT_TYPE_AUTH_PROC_SUSPEND_RESUME = 92,
    ES_EVENT_TYPE_NOTIFY_PROC_SUSPEND_RESUME = 93,
    ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED = 94,
    ES_EVENT_TYPE_NOTIFY_GET_TASK_NAME = 95,
    ES_EVENT_TYPE_NOTIFY_TRACE = 96,
    ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE = 97,
    ES_EVENT_TYPE_AUTH_REMOUNT = 98,
    --
    ES_EVENT_TYPE_NOTIFY_REMOUNT = 99,

    == MACOS_11_3_0;
    ES_EVENT_TYPE_AUTH_GET_TASK_READ = 100,
    ES_EVENT_TYPE_NOTIFY_GET_TASK_READ = 101,
    --
    ES_EVENT_TYPE_NOTIFY_GET_TASK_INSPECT = 102,

    == MACOS_12_0_0;
    ES_EVENT_TYPE_NOTIFY_SETUID = 103,
    ES_EVENT_TYPE_NOTIFY_SETGID = 104,
    ES_EVENT_TYPE_NOTIFY_SETEUID = 105,
    ES_EVENT_TYPE_NOTIFY_SETEGID = 106,
    ES_EVENT_TYPE_NOTIFY_SETREUID = 107,
    ES_EVENT_TYPE_NOTIFY_SETREGID = 108,
    ES_EVENT_TYPE_AUTH_COPYFILE = 109,
    --
    ES_EVENT_TYPE_NOTIFY_COPYFILE = 110,

    == MACOS_13_0_0;
    ES_EVENT_TYPE_NOTIFY_AUTHENTICATION = 111,
    ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED = 112,
    ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED = 113,
    ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN = 114,
    ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGOUT = 115,
    ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOCK = 116,
    ES_EVENT_TYPE_NOTIFY_LW_SESSION_UNLOCK = 117,
    ES_EVENT_TYPE_NOTIFY_SCREENSHARING_ATTACH = 118,
    ES_EVENT_TYPE_NOTIFY_SCREENSHARING_DETACH = 119,
    ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN = 120,
    ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT = 121,
    ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN = 122,
    ES_EVENT_TYPE_NOTIFY_LOGIN_LOGOUT = 123,
    ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD = 124,
    --
    ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE = 125,
);

ffi_wrap_enum!(
    /// Valid authorization values to be used when responding to a
    /// [`es_message_t`][super::es_message_t] auth event
    es_auth_result_t(u32);

    == MACOS_10_15_0;
    /// The event is authorized and should be allowed to continue
    ES_AUTH_RESULT_ALLOW = 0,
    --
    /// The event is not authorized and should be blocked
    ES_AUTH_RESULT_DENY = 1,
);

ffi_wrap_enum!(
    /// Valid authorization values to be used when responding to a
    /// [`es_message_t`][super::es_message_t] auth event
    es_result_type_t(u32);

    == MACOS_10_15_0;
    /// The event is authorized and should be allowed to continue
    ES_RESULT_TYPE_AUTH = 0,
    --
    /// The event is not authorized and should be blocked
    ES_RESULT_TYPE_FLAGS = 1,
);

ffi_wrap_enum!(
    /// Return value for functions that can only fail in one way
    es_return_t(u32);

    == MACOS_10_15_0;
    /// Function was successful
    ES_RETURN_SUCCESS = 0,
    --
    /// Function failed
    ES_RETURN_ERROR = 1,
);

ffi_wrap_enum!(
    /// Error conditions for responding to a message
    es_respond_result_t(u32);

    == MACOS_10_15_0;
    /// Success case
    ES_RESPOND_RESULT_SUCCESS = 0,
    /// One or more invalid arguments were provided
    ES_RESPOND_RESULT_ERR_INVALID_ARGUMENT = 1,
    /// Communication with the ES subsystem failed
    ES_RESPOND_RESULT_ERR_INTERNAL = 2,
    /// The message being responded to could not be found
    ES_RESPOND_RESULT_NOT_FOUND = 3,
    /// The provided message has been responded to more than once
    ES_RESPOND_RESULT_ERR_DUPLICATE_RESPONSE = 4,
    --
    /// Either an inappropriate response API was used for the event type (ensure using proper
    /// [`es_respond_auth_result`][super::es_respond_auth_result] or
    /// [`es_respond_flags_result`][super::es_respond_flags_result] function) or the event is
    /// notification only.
    ES_RESPOND_RESULT_ERR_EVENT_TYPE = 5,
);

ffi_wrap_enum!(
    /// Error conditions for creating a new client
    es_new_client_result_t(u32);

    == MACOS_10_15_0;
    /// Success case
    ES_NEW_CLIENT_RESULT_SUCCESS = 0,
    /// One or more invalid arguments were provided.
    ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT = 1,
    /// Communication with the ES subsystem failed, or other error condition.
    ES_NEW_CLIENT_RESULT_ERR_INTERNAL = 2,
    /// The caller is not properly entitled to connect.
    ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED = 3,
    /// The caller lacks Transparency, Consent, and Control (TCC) approval from the user.
    ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED = 4,
    --
    /// The caller is not running as root.
    ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED = 5,

    == MACOS_10_15_1;
    --
    /// The caller has reached the maximum number of allowed simultaneously connected clients.
    ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS = 6,
);

ffi_wrap_enum!(
    /// Error conditions for clearing the authorisation caches
    es_clear_cache_result_t(u32);

    == MACOS_10_15_0;
    /// Success case
    ES_CLEAR_CACHE_RESULT_SUCCESS = 0,
    /// Communication with the ES subsystem failed
    ES_CLEAR_CACHE_RESULT_ERR_INTERNAL = 1,
    --
    /// Rate of calls is too high. Slow down.
    ES_CLEAR_CACHE_RESULT_ERR_THROTTLE = 2,
);

/// Structure buffer with size
#[repr(C)]
pub struct es_token_t {
    /// Size of the `data` field, in bytes
    pub size: size_t,
    pub data: *const u8,
}

slice_access!(es_token_t[.data; .size]: fn as_slice() -> u8);

/// Structure for handling strings
#[repr(C)]
pub struct es_string_token_t {
    /// Size of the `data` field, equivalent to `strlen()`
    pub length: size_t,
    pub data: *const c_char,
}

impl es_string_token_t {
    /// See the data as an [`OsStr`]
    ///
    /// # Safety
    ///
    /// `length` and `data` should be in sync. If `length` is not 0, `data` should be a non-null
    /// pointer to initialized data of the correct number of bytes.
    pub unsafe fn as_os_str(&self) -> &OsStr {
        if self.length > 0 && self.data.is_null() == false {
            // Safety: `data` is non-null and `length` is the non-zero number of elements (which is
            // also the size in bytes in this case). Alignement is always correct since it's for a
            // slice of `u8` (on macOS, `OsStr` are a bag of bytes)
            let raw: &[u8] = unsafe { from_raw_parts(self.data.cast(), self.length) };
            OsStr::from_bytes(raw)
        } else {
            OsStr::from_bytes(&[])
        }
    }
}

ffi_wrap_enum!(
    /// Values that will be paired with path strings to describe the type of the path
    es_mute_path_type_t(u32);

    == MACOS_10_15_0;
    /// Value to describe a path prefix
    ES_MUTE_PATH_TYPE_PREFIX = 0,
    --
    /// Value to describe a path literal
    ES_MUTE_PATH_TYPE_LITERAL = 1,

    == MACOS_13_0_0;
    /// Value to describe a target path prefix
    ES_MUTE_PATH_TYPE_TARGET_PREFIX = 2,
    --
    /// Value to describe a target path literal
    ES_MUTE_PATH_TYPE_TARGET_LITERAL = 3,
);

/// Structure to describe attributes of a muted path
#[repr(C)]
pub struct es_muted_path_t {
    /// Indicates if the path is a prefix or literal, and what type of muting applies
    pub type_: es_mute_path_type_t,
    /// The number of events contained in the `events` array
    pub event_count: size_t,
    /// Array of event types for which the path is muted
    pub events: *const es_event_type_t,
    /// The muted path. (Note: `es_string_token_t` is a `char` array and length)
    pub path: es_string_token_t,
}

slice_access!(es_muted_path_t[.events; .event_count]: fn events() -> es_event_type_t);

/// Structure for a set of muted paths
#[repr(C)]
pub struct es_muted_paths_t {
    /// Number of elements in the `paths` array
    pub count: size_t,
    /// Array of muted paths
    pub paths: *const es_muted_path_t,
}

slice_access!(es_muted_paths_t[.paths; .count]: fn paths() -> es_muted_path_t);

/// Structure to describe attributes of a muted process
#[repr(C)]
pub struct es_muted_process_t {
    /// The audit token of a muted process
    pub audit_token: audit_token_t,
    /// The number of events contained in the `events` array
    pub event_count: size_t,
    /// Array of event types for which the process is muted
    pub events: *const es_event_type_t,
}

slice_access!(es_muted_process_t[.events; .event_count]: fn events() -> es_event_type_t);

/// Structure for a set of muted processes
#[repr(C)]
pub struct es_muted_processes_t {
    /// Number of elements in the `processes` array
    count: size_t,
    /// Array of muted processes
    processes: *const es_muted_process_t,
}

slice_access!(es_muted_processes_t[.processes; .count]: fn processes() -> es_muted_process_t);

#[cfg(feature = "macos_13_0_0")]
ffi_wrap_enum!(
    /// Type of a network address.
    es_address_type_t(u32);

    == MACOS_13_0_0;
    /// No source address available.
    ES_ADDRESS_TYPE_NONE = 0,
    /// Source address is IPv4.
    ES_ADDRESS_TYPE_IPV4 = 1,
    /// Source address is IPv6.
    ES_ADDRESS_TYPE_IPV6 = 2,
    --
    /// Source address is named UNIX socket.
    ES_ADDRESS_TYPE_NAMED_SOCKET = 3,
);

#[cfg(feature = "macos_13_0_0")]
ffi_wrap_enum!(
    es_mute_inversion_type_t(u32);
    == MACOS_13_0_0;

    ES_MUTE_INVERSION_TYPE_PROCESS = 0,
    ES_MUTE_INVERSION_TYPE_PATH = 1,
    ES_MUTE_INVERSION_TYPE_TARGET_PATH = 2,
    --
    ES_MUTE_INVERSION_TYPE_LAST = 4,
);

#[cfg(feature = "macos_13_0_0")]
ffi_wrap_enum!(
    /// Return type for mute inversion
    es_mute_inverted_return_t(u32);

    == MACOS_13_0_0;
    /// The type of muted queried was inverted
    ES_MUTE_INVERTED = 0,
    /// The type of muted queried was not inverted
    ES_MUTE_NOT_INVERTED = 1,
    --
    /// There was an error querying mute inversion state
    ES_MUTE_INVERTED_ERROR = 2,
);
