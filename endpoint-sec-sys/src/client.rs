//! Corresponding header: `EndpointSecurity/ESClient.h`

// Types and methods should be added in the same order as they are in the original header to make
// maintenance easier.

use core::marker::PhantomData;
use core::ptr::NonNull;

pub use block2;
use block2::Block;
use libc::c_char;
pub use libc::c_void;
use objc2_encode::{Encoding, RefEncode};

use super::{
    audit_token_t, es_auth_result_t, es_clear_cache_result_t, es_event_type_t, es_message_t, es_new_client_result_t,
    es_respond_result_t, es_return_t,
};
#[cfg(feature = "macos_13_0_0")]
use super::{es_mute_inversion_type_t, es_mute_inverted_return_t};
#[cfg(feature = "macos_12_0_0")]
use super::{es_mute_path_type_t, es_muted_paths_t, es_muted_processes_t};

/// Opaque type that stores the endpoint security client state.
///
/// Neither [`Send`] nor [`Sync`].
#[repr(transparent)]
pub struct es_client_t(u8, PhantomData<*mut u8>);

unsafe impl RefEncode for es_client_t {
    const ENCODING_REF: Encoding = Encoding::Pointer(&Encoding::Unknown);
}

#[link(name = "EndpointSecurity", kind = "dylib")]
extern "C" {
    /// Subscribe to some set of events
    ///
    /// - `client`: The client that will be subscribing
    /// - `events`: Array of es_event_type_t to subscribe to
    /// - `event_count`: Count of es_event_type_t in `events`
    ///
    /// Subscribing to new event types does not remove previous subscriptions.
    ///
    /// Subscribing to events is not optional for clients that have opted into early boot mode (see
    /// `NSEndpointSecurityEarlyBoot` in `EndpointSecurity(7)`). Early boot clients that fail to
    /// subscribe to at least one event type will cause early boot to time out, resulting in a bad
    /// user experience and risking watchdog timeout panics.
    pub fn es_subscribe(client: *mut es_client_t, events: *const es_event_type_t, event_count: u32) -> es_return_t;

    /// Unsubscribe from some set of events
    ///
    /// - `client`: The client that will be unsubscribing
    /// - `events`: Array of es_event_type_t to unsubscribe from
    /// - `event_count`: Count of es_event_type_t in `events`
    ///
    /// Events not included in the given `events` array that were previously subscribed to will
    /// continue to be subscribed to.
    pub fn es_unsubscribe(client: *mut es_client_t, events: *const es_event_type_t, event_count: u32) -> es_return_t;

    /// Unsubscribe from all events
    ///
    /// - `client`: The client that will be unsubscribing
    pub fn es_unsubscribe_all(client: *mut es_client_t) -> es_return_t;

    /// List subscriptions
    ///
    /// - `client`: The client for which subscriptions will be listed
    /// - `count`: Out param that reports the number of subscriptions written
    /// - `subscriptions`:  Out param for pointer to subscription data
    ///
    /// The caller takes ownership of the memory at `*subscriptions` and must free it.
    pub fn es_subscriptions(
        client: *mut es_client_t,
        count: *mut usize,
        subscriptions: *mut *mut es_event_type_t,
    ) -> es_return_t;

    /// Respond to an auth event that requires an [`es_auth_result_t`] response
    ///
    /// - `client`: The client that produced the event
    /// - `message`: The message being responded to
    /// - `result`: A result indicating the action the ES subsystem should take
    /// - `cache`: Indicates if this result should be cached. The specific caching semantics depend
    ///            on [`es_event_type_t`].
    ///            Cache key is generally the involved files, with modifications to those files
    ///            invalidating the cache entry. A cache hit leads to no AUTH event being produced,
    ///            while still producing a NOTIFY event normally. The cache argument is ignored for
    ///            events that do not support caching.
    ///
    /// Some events must be responded to with [`es_respond_flags_result()`]. Responding to flags
    /// events with this function will fail.
    pub fn es_respond_auth_result(
        client: *mut es_client_t,
        message: *const es_message_t,
        result: es_auth_result_t,
        cache: bool,
    ) -> es_respond_result_t;

    /// Respond to an auth event that requires an `u32` flags response
    ///
    /// - `client`: The client that produced the event
    /// - `message`: The message being responded to
    /// - `authorized_flags`: A flags value that will mask the flags in event being responded to;
    ///                       pass 0 to deny and `u32::MAX` to allow regardless of what flags are
    ///                       set on the event.
    /// - `cache`: Indicates if this result should be cached. The specific caching semantics depend
    ///            on [`es_event_type_t`].
    ///            Cache key is generally the involved files, with modifications to those files
    ///            invalidating the cache entry. A cache hit leads to no AUTH event being produced,
    ///            while still producing a NOTIFY event normally. The cache argument is ignored for
    ///            events that do not support caching.
    ///
    /// Some events must be responded to with [`es_respond_auth_result()`]. Responding to auth
    /// events with the function will fail.
    ///
    /// Enabling caching caches `authorized_flags`. Subsequent cache hits will result in the
    /// event being allowed only if the flags of the event are a subset of the flags in
    /// `authorized_flags`, and denied otherwise. As a result, `u32::MAX` should be passed
    /// for `authorized_flags`, unless denying events with certain flags is intentional.
    /// A common mistake is passing the flags from the event, which together with caching
    /// may result in subsequent events getting unintentionally denied if they have flags
    /// set that were not set in the cached `authorized_flags`.
    pub fn es_respond_flags_result(
        client: *mut es_client_t,
        message: *const es_message_t,
        authorized_flags: u32,
        cache: bool,
    ) -> es_respond_result_t;

    /// Suppress all events from the process described by the given `audit_token`
    ///
    /// - `client`: The client for which events will be suppressed
    /// - `audit_token`: The audit token of the process for which events will be suppressed
    ///
    #[cfg_attr(feature = "macos_12_0_0", doc = "See [`es_mute_process_events()`]")]
    #[cfg_attr(not(feature = "macos_12_0_0"), doc = "See `es_mute_process_events()`")]
    pub fn es_mute_process(client: *mut es_client_t, audit_token: *const audit_token_t) -> es_return_t;

    /// Suppress a subset of events from the process described by the given `audit_token`
    ///
    /// - `client`: The client for which events will be suppressed
    /// - `audit_token`: The audit token of the process for which events will be suppressed
    /// - `events`: Array of event types for which the audit_token should be muted.
    /// - `event_count`: The number of items in the `events` array.
    ///
    /// See [`es_mute_process()`]
    #[cfg(feature = "macos_12_0_0")]
    pub fn es_mute_process_events(
        client: *mut es_client_t,
        audit_token: *const audit_token_t,
        events: *const es_event_type_t,
        event_count: usize,
    ) -> es_return_t;

    /// Unmute a process for all event types
    ///
    /// - `client`: The client for which the process will be unmuted
    /// - `audit_token`: The audit token of the process to be unmuted
    ///
    #[cfg_attr(feature = "macos_12_0_0", doc = "See [`es_unmute_process_events()`]")]
    #[cfg_attr(not(feature = "macos_12_0_0"), doc = "See `es_unmute_process_events()`")]
    pub fn es_unmute_process(client: *mut es_client_t, audit_token: *const audit_token_t) -> es_return_t;

    /// Unmute a process for a subset of event types.
    ///
    /// - `client`: The client for which events will be unmuted
    /// - `audit_token`: The audit token of the process for which events will be unmuted
    /// - `events`: Array of event types to unmute for the process
    /// - `event_count`: The number of items in the `events` array.
    ///
    /// See [`es_unmute_path()`]
    #[cfg(feature = "macos_12_0_0")]
    pub fn es_unmute_process_events(
        client: *mut es_client_t,
        audit_token: *const audit_token_t,
        events: *const es_event_type_t,
        event_count: usize,
    ) -> es_return_t;

    /// List muted processes
    ///
    /// - `client`: The client for which muted processes will be listed
    /// - `count`: Out param that reports the number of audit tokens written
    /// - `audit_tokens`:  Out param for pointer to audit_token data
    ///
    /// The caller takes ownership of the memory at `*audit_tokens` and must free it. If there
    /// are no muted processes and the call completes successfully, `*count` is set to 0 and
    /// `*audit_token` is set to `NULL`.
    ///
    /// The audit tokens are returned in the same state as they were passed to [`es_mute_process()`]
    /// and may not accurately reflect the current state of the respective processes.
    pub fn es_muted_processes(
        client: *mut es_client_t,
        count: *mut usize,
        audit_tokens: *mut *mut audit_token_t,
    ) -> es_return_t;

    /// Retrieve a list of all muted processes.
    ///
    /// - `client`: The es_client_t for which the muted processes will be retrieved.
    /// - `muted_processes`: OUT param the will contain newly created memory describing the set of
    ///  muted processes. This memory must be deleted using [`es_release_muted_processes`].
    ///
    /// See [`es_release_muted_processes()`]
    #[cfg(feature = "macos_12_0_0")]
    pub fn es_muted_processes_events(
        client: *mut es_client_t,
        muted_processes: *mut *mut es_muted_processes_t,
    ) -> es_return_t;

    /// Delete a set of muted processes obtained from `es_muted_processes_events`, freeing resources.
    ///
    /// - `muted_processes`: A set of muted processes to delete.
    ///
    /// See [`es_muted_processes_events()`]
    #[cfg(feature = "macos_12_0_0")]
    pub fn es_release_muted_processes(muted_processes: *mut es_muted_processes_t);

    /// Suppress all events matching a path.
    ///
    /// - `client`: The es_client_t for which the path will be muted.
    /// - `path`: The path to mute.
    /// - `type`: Describes the type of the `path` parameter.
    ///
    /// Path-based muting applies to the real and potentially firmlinked path of a file as seen by
    /// VFS, and as available from `fcntl(2)` `F_GETPATH`. No special provisions are made for files
    /// with multiple ("hard") links, or for symbolic links.
    ///
    /// In particular, when using inverted target path muting to monitor a particular path for
    /// writing, you will need to check if the file(s) of interest are also reachable via additional
    /// hard links outside of the paths you are observing.
    ///
    /// See [`es_mute_path_events()`]
    ///
    /// When using the path types `ES_MUTE_PATH_TYPE_TARGET_PREFIX` and
    /// `ES_MUTE_PATH_TYPE_TARGET_LITERAL` not all events are supported. Furthermore the
    /// interpretation of target path is contextual. For events with more than one target path (such
    /// as [`es_event_exchangedata_t`][crate::es_event_exchangedata_t]) the behavior depends on the
    /// mute inversion state:
    ///
    /// - Under normal muting the event is suppressed only if **ALL** paths are muted
    /// - When target path muting is inverted the event is selected if **ANY** target path is muted
    ///
    /// For example a rename will be suppressed if and only if both the source path and destination
    /// path are muted. Supported events are listed below. For each event the target path is defined
    /// as:
    ///
    /// - [`EXEC`][crate::es_event_exec_t]:
    ///        The file being executed
    /// - [`OPEN`][crate::es_event_open_t]:
    ///        The file being opened
    /// - [`MMAP`][crate::es_event_mmap_t]:
    ///        The file being memeory mapped
    /// - [`RENAME`][crate::es_event_rename_t]:
    ///        Both the source and destination path.
    /// - [`SIGNAL`][crate::es_event_signal_t]:
    ///        The path of the process being signalled
    /// - [`UNLINK`][crate::es_event_unlink_t]:
    ///        The file being unlinked
    /// - [`CLOSE`][crate::es_event_close_t]:
    ///        The file being closed
    /// - [`CREATE`][crate::es_event_create_t]:
    ///        The path to the file that will be created or replaced
    /// - [`GET_TASK`][crate::es_event_get_task_t]:
    ///        The path of the process for which the task port
    ///   is being retrieved
    /// - [`LINK`][crate::es_event_link_t]:
    ///        Both the source and destination path
    /// - [`SETATTRLIST`][crate::es_event_setattrlist_t]:
    ///        The file for which the attributes are being set
    /// - [`SETEXTATTR`][crate::es_event_setextattr_t]:
    ///        The file for which the extended attributes are being set
    /// - [`SETFLAGS`][crate::es_event_setflags_t]:
    ///        The file for which flags are being set
    /// - [`SETMODE`][crate::es_event_setmode_t]:
    ///        The file for which the mode is being set
    /// - [`SETOWNER`][crate::es_event_setowner_t]:
    ///        The file for which the owner is being set
    /// - [`WRITE`][crate::es_event_write_t]:
    ///        The file being written to
    /// - [`READLINK`][crate::es_event_readlink_t]:
    ///        The symbolic link being resolved
    /// - [`TRUNCATE`][crate::es_event_truncate_t]:
    ///        The file being truncated
    /// - [`CHDIR`][crate::es_event_chdir_t]:
    ///        The new working directory
    /// - [`GETATTRLIST`][crate::es_event_getattrlist_t]:
    ///        The file for which the attribute list is being retrieved
    /// - [`STAT`][crate::es_event_stat_t]:
    ///        The file for which the stat is being retrieved
    /// - [`ACCESS`][crate::es_event_access_t]:
    ///        The file for which access is being tested
    /// - [`CHROOT`][crate::es_event_chroot_t]:
    ///        The file which will become the new root
    /// - [`UTIMES`][crate::es_event_utimes_t]:
    ///        The file for which times are being set
    /// - [`CLONE`][crate::es_event_clone_t]:
    ///        Both the source file and target path
    /// - [`FCNTL`][crate::es_event_fcntl_t]:
    ///        The file under file control
    /// - [`GETEXTATTR`][crate::es_event_getextattr_t]:
    ///        The file for which extended attributes are being retrieved
    /// - [`LISTEXTATTR`][crate::es_event_listextattr_t]:
    ///        The file for which extended attributes are being listed
    /// - [`READDIR`][crate::es_event_readdir_t]:
    ///        The directory for whose contents will be read
    /// - [`DELETEEXTATTR`][crate::es_event_deleteextattr_t]:
    ///        The file for which extended attribtes will be deleted
    /// - [`DUP`][crate::es_event_dup_t]:
    ///        The file being duplicated
    /// - [`UIPC_BIND`][crate::es_event_uipc_bind_t]:
    ///        The path to the unix socket that will be created
    /// - [`UIPC_CONNECT`][crate::es_event_uipc_connect_t]:
    ///        The file that the unix socket being connected is bound to
    /// - [`EXCHANGEDATA`][crate::es_event_exchangedata_t]:
    ///        The path of both file1 and file2
    /// - [`SETACL`][crate::es_event_setacl_t]:
    ///        The file for which ACLs are being set
    /// - [`PROC_CHECK`][crate::es_event_proc_check_t]:
    ///        The path of the process against which access is beign checked
    /// - [`SEARCHFS`][crate::es_event_searchfs_t]:
    ///        The path of the volume which will be searched
    /// - [`PROC_SUSPEND_RESUME`][crate::es_event_proc_suspend_resume_t]:
    ///        The path of the process being suspended or resumed
    /// - [`GET_TASK_NAME`][crate::es_event_get_task_name_t]:
    ///        The path of the process for which the task name port will be retrieved
    /// - [`TRACE`][crate::es_event_trace_t]:
    ///        The path of the process that will be attached to
    /// - [`REMOTE_THREAD_CREATE`][crate::es_event_remote_thread_create_t]:
    ///        The path of the process in which the new thread is created
    /// - [`GET_TASK_READ`][crate::es_event_get_task_read_t]:
    ///        The path of the process for which the task read port will be retrieved
    /// - [`GET_TASK_INSPECT`][crate::es_event_get_task_inspect_t]:
    ///        The path of the process for which the task inspect port will be retrieved
    /// - [`COPYFILE`][crate::es_event_copyfile_t]:
    ///        The path to the source file and the path to either the new file to be created or the
    ///        existing file to be overwritten
    #[cfg(feature = "macos_12_0_0")]
    pub fn es_mute_path(client: *mut es_client_t, path: *const c_char, type_: es_mute_path_type_t) -> es_return_t;

    /// Suppress a subset of events matching a path.
    ///
    /// - `client`: The es_client_t for which the path will be muted.
    /// - `path`: The path to mute.
    /// - `type`: Describes the type of the `path` parameter, either a prefix path or literal path.
    /// - `events`: Array of event types for which the path should be muted.
    /// - `event_count`: The number of items in the `events` array.
    ///
    /// See [`es_mute_path()`]
    ///
    /// When using `ES_MUTE_PATH_TYPE_TARGET_PREFIX` and `ES_MUTE_PATH_TYPE_TARGET_LITERAL` not
    /// all events are supported. Target muting a path for an event type that does not support
    /// target muting is a no-op. If at least one event type was muted for a target path then
    /// `ES_RETURN_SUCCESS` is returned. If all specified event types do not support target muting
    /// `ES_RETURN_ERROR` is returned. See [`es_mute_path()`] for the list of events that support
    /// target path muting.
    #[cfg(feature = "macos_12_0_0")]
    pub fn es_mute_path_events(
        client: *mut es_client_t,
        path: *const c_char,
        type_: es_mute_path_type_t,
        events: *const es_event_type_t,
        event_count: usize,
    ) -> es_return_t;

    /// Suppress events matching a path prefix
    ///
    #[cfg_attr(
        feature = "macos_12_0_0",
        doc = "**Deprecated in macOS 12**: Please use [`es_mute_path()`] or [`es_mute_path_events()`]"
    )]
    #[cfg_attr(
        not(feature = "macos_12_0_0"),
        doc = "**Deprecated in macOS 12**: Please use `es_mute_path()` or `es_mute_path_events()`"
    )]
    ///
    /// - `client`: The client for which events will be suppressed
    /// - `path_prefix`: The path against which supressed executables must prefix match
    pub fn es_mute_path_prefix(client: *mut es_client_t, path_prefix: *const c_char) -> es_return_t;

    /// Suppress events matching a path literal
    ///
    #[cfg_attr(
        feature = "macos_12_0_0",
        doc = "**Deprecated in macOS 12**: Please use [`es_mute_path()`] or [`es_mute_path_events()`]"
    )]
    #[cfg_attr(
        not(feature = "macos_12_0_0"),
        doc = "**Deprecated in macOS 12**: Please use `es_mute_path()` or `es_mute_path_events()`"
    )]
    ///
    /// - `client`: The client for which events will be suppressed
    /// - `path_literal`: The path against which supressed executables must match exactly
    ///
    #[cfg_attr(
        feature = "macos_12_0_0",
        doc = "See [`es_mute_path()`] and [`es_mute_path_events()`]"
    )]
    #[cfg_attr(
        not(feature = "macos_12_0_0"),
        doc = "See `es_mute_path()` and `es_mute_path_events()`"
    )]
    pub fn es_mute_path_literal(client: *mut es_client_t, path_literal: *const c_char) -> es_return_t;

    /// Unmute all paths
    ///
    /// - `client`: The client for which all currently muted paths will be unmuted
    ///
    #[cfg_attr(
        feature = "macos_13_0_0",
        doc = "Only unmutes **executable** paths. To unmute target paths see [`es_unmute_all_target_paths()`]."
    )]
    #[cfg_attr(
        not(feature = "macos_13_0_0"),
        doc = "Only unmutes **executable** paths. To unmute target paths see `es_unmute_all_target_paths()`."
    )]
    pub fn es_unmute_all_paths(client: *mut es_client_t) -> es_return_t;

    /// Unmute all target paths
    ///
    /// - `client`: The client for which all currently muted target paths will be unmuted
    ///
    /// See [`es_unmute_all_paths()`]
    #[cfg(feature = "macos_13_0_0")]
    pub fn es_unmute_all_target_paths(client: *mut es_client_t) -> es_return_t;

    /// Unmute a path for all event types.
    ///
    /// - `client`: The es_client_t for which the path will be unmuted.
    /// - `path`: The path to unmute.
    /// - `type`: Describes the type of the `path` parameter, either a prefix path or literal path.
    ///
    /// Muting and unuting operations logically work on a set of `(path_type, path,
    /// es_event_type_t)` tuples Subtracting an element from the set that is not present has no
    /// effect For example if `(literal, /foo/bar/, *)` is muted Then `(prefix, /foo, *)` is unmuted
    /// the mute set is still: `(literal, /foo/bar, *)`. Prefixes only apply to mute evaluation not
    /// to modifications of the mute set.
    ///
    /// See [`es_unmute_path_events()`]
    #[cfg(feature = "macos_12_0_0")]
    pub fn es_unmute_path(client: *mut es_client_t, path: *const c_char, type_: es_mute_path_type_t) -> es_return_t;

    /// Unmute a path for a subset of event types.
    ///
    /// - `client`: The es_client_t for which the path will be unmuted.
    /// - `path`: The path to unmute.
    /// - `type`: Describes the type of the `path` parameter, either a prefix path or literal path.
    /// - `events`: Array of event types for which the path should be unmuted.
    /// - `event_count`: The number of items in the `events` array.
    ///
    /// See [`es_unmute_path()`]
    #[cfg(feature = "macos_12_0_0")]
    pub fn es_unmute_path_events(
        client: *mut es_client_t,
        path: *const c_char,
        type_: es_mute_path_type_t,
        events: *const es_event_type_t,
        event_count: usize,
    ) -> es_return_t;

    /// Retrieve a list of all muted paths.
    ///
    /// - `client`: The es_client_t for which the muted paths will be retrieved.
    /// - `muted_paths`: OUT param the will contain newly created memory describing the set of
    ///  muted paths. This memory must be deleted using [`es_release_muted_paths()`].
    ///
    /// See [`es_release_muted_paths()`]
    #[cfg(feature = "macos_12_0_0")]
    pub fn es_muted_paths_events(client: *mut es_client_t, muted_paths: *mut *mut es_muted_paths_t) -> es_return_t;

    /// Delete a set of muted paths obtained from `es_muted_paths_events`, freeing resources.
    ///
    /// - `muted_paths`: A set of muted paths to delete.
    ///
    /// See [`es_muted_paths_events()`]
    #[cfg(feature = "macos_12_0_0")]
    pub fn es_release_muted_paths(muted_paths: *mut es_muted_paths_t);

    /// Invert the mute state of a given mute dimension
    ///
    /// - `client`: The `es_client_t` for which muting will be inverted
    /// - `mute_type`: The type of muting to invert (process, path, or target path).
    ///
    /// Inverting muting can be used to create a client that monitors a specific process(es) or set
    /// of directories When muting is inverted it still combines with other types of muting using
    /// `OR`, and inversion happens first.
    ///
    /// Consider a series of inputs for a system where PID 12 is muted, process muting is inverted,
    /// and `/bin/bash` is also path muted:
    ///
    /// - `(12, /bin/foo)  MATCHING (true, false)  INVERSION (false, false) || false` → event is **not** suppressed
    /// - `(13, /bin/foo)  MATCHING (false, false) INVERSION (true, false)  || true`  → event is suppressed
    /// - `(12, /bin/bash) MATCHING (true, true)   INVERSION (false, true)  || true`  → event is suppressed
    ///
    ///   Note that because muting is combined using OR even when pid 12 is being selected using
    ///   inverted process muting, (12, /bin/bash) is still suppressed because the path is muted
    ///
    /// The relationship between all three types of muting (proc,path,target-path) and how each
    /// can be inverted is complex. The below flow chart explains in detail exactly how muting is
    /// applied in the kernel:
    ///
    /// ```text
    /// ┌──────────────────┐
    /// │      Event       │
    /// └──────────────────┘
    ///           │
    ///           ▼
    /// ┌──────────────────┐                                           ┌──────────────────┐
    /// │  Is Subscribed?  │────No────────────────────────────────────▶│  Suppress Event  │
    /// └──────────────────┘                                           └──────────────────┘
    ///           │                                                              ▲
    ///        Yes│                                                              │
    ///           ▼                ┌────────────────┐                            │
    /// ┌──────────────────┐       │ Is Proc Muting │                            │
    /// │  Is Proc Muted?  ├─Yes──▶│   Inverted?    ├──No───────────────────────▶│
    /// └─────────┬────────┘       └────────────────┘                            │
    ///           │                         │                                    │
    ///         No│                        Yes                                   │
    ///           ▼                         │                                    │
    /// ┌──────────────────┐                │                                    │
    /// │  Is Proc Muting  │                │                                    │
    /// │    Inverted?     │──Yes───────────)───────────────────────────────────▶│
    /// └─────────┬────────┘                │                                    │
    ///           │                         │                                    │
    ///         No│◀────────────────────────┘                                    │
    ///           ▼                 ┌───────────────┐                            │
    /// ┌──────────────────┐        │Is Path Muting │                            │
    /// │  Is Path Muted?  │──Yes──▶│   Inverted?   ├──No───────────────────────▶│
    /// └─────────┬────────┘        └───────┬───────┘                            │
    ///           │                         │                                    │
    ///         No│                        Yes                                   │
    ///           ▼                         │                                    │
    /// ┌──────────────────┐                │                                    │
    /// │  Is Path Muting  │                │                                    │
    /// │    Inverted?     │──Yes───────────)───────────────────────────────────▶│
    /// └─────────┬────────┘                │                                    │
    ///           │                         │                                    │
    ///         No│◀────────────────────────┘                                    │
    ///           ▼                                                              │
    /// ┌──────────────────┐                                                     │
    /// │  Event Supports  │      ┌───────────────┐      ┌─────────────────┐     │
    /// │   Target Path    │─Yes─▶│Is Target Path ├─Yes─▶│ Are ANY target  ├─No─▶│
    /// │     Muting?      │      │Muting Inverted│      │  paths muted?   │     │
    /// └──────────────────┘      └──────┬────────┘      └───────┬─────────┘     │
    ///           │                      │                       │               │
    ///         No│                    No│                      Yes              │
    ///           │                      ▼                       │               │
    ///           │              ┌────────────────┐              │               │
    ///           │              │ Are ALL target │              │               │
    ///           │              │  paths muted?  ├─Yes──────────)───────────────┘
    ///           │              └───────┬────────┘              │
    ///           │                      │                       │
    ///           │                    No│                       │
    ///           │◀─────────────────────┘                       │
    ///           │                                              │
    ///           │◀─────────────────────────────────────────────┘
    ///           │
    ///           ▼
    /// ┌──────────────────┐
    /// │  Deliver Event   │
    /// └──────────────────┘
    /// ```
    ///
    /// Mute inversion does **NOT** clear the default mute set. When a new `es_client_t` is created
    /// certain paths are muted by default. This is known as "the default mute set". The default
    /// mute set exists to protect ES clients from deadlocks, and to prevent watchdog timeout
    /// panics. Creating a new client and calling `es_invert_muting(c, ES_MUTE_INVERSION_TYPE_PATH)`
    /// will result in the default mute set being selected rather than muted. In most cases this
    /// is unintended.
    ///
    /// - Consider calling [`es_unmute_all_paths()`] before inverting process path muting.
    /// - Consider calling [`es_unmute_all_target_paths()`] before inverting target path muting.
    ///
    /// Make sure the client has no AUTH subscriptions before doing so. If desired the default mute
    /// set can be saved using [`es_muted_paths_events()`] and then restored after inverting again.
    #[cfg(feature = "macos_13_0_0")]
    pub fn es_invert_muting(client: *mut es_client_t, mute_type: es_mute_inversion_type_t) -> es_return_t;

    /// Query mute inversion state
    ///
    /// - `client`: The `es_client_t` for which mute inversion state is being queried.
    /// - `mute_type`: The type of muting to query (process, path, or target path).
    #[cfg(feature = "macos_13_0_0")]
    pub fn es_muting_inverted(
        client: *mut es_client_t,
        mute_type: es_mute_inversion_type_t,
    ) -> es_mute_inverted_return_t;

    /// Clear all cached results for all clients.
    ///
    /// - `client`: that will perform the request
    ///
    /// This functions clears the shared cache for all ES clients and is hence
    /// rate limited. If `es_clear_cache` is called too frequently it will return
    /// `ES_CLEAR_CACHE_RESULT_ERR_THROTTLE`.
    ///
    /// It is permissible to pass any valid `es_client_t` object created by `es_new_client`.
    pub fn es_clear_cache(client: *mut es_client_t) -> es_clear_cache_result_t;
}

/// The type of block that will be invoked to handled messages from the ES subsystem
///
/// - The `es_client_t` is a handle to the client being sent the event. It must be passed to any
///  "respond" functions
/// - The `es_message_t` is the message that must be handled. Mutating it is forbidden but Rust
///  does not expose a `ConstNonNull` type.
pub type es_handler_block_t = Block<(NonNull<es_client_t>, NonNull<es_message_t>), ()>;

#[link(name = "EndpointSecurity", kind = "dylib")]
extern "C" {
    /// Initialise a new `es_client_t` and connect to the ES subsystem
    ///
    /// - `client`: Out param. On success this will be set to point to the newly allocated [`es_client_t`].
    /// - `handler`: The handler block that will be run on all messages sent to this client
    ///
    /// Messages are handled strictly serially and in the order they are delivered. Returning
    /// control from the handler causes the next available message to be dequeued. Messages can
    /// be responded to out of order by returning control before calling `es_respond_*`. The
    /// `es_message_t` is only guaranteed to live as long as the scope it is passed into. The
    /// memory for the given `es_message_t` is NOT owned by clients and it must not be freed. For
    /// out of order responding the handler must retain the message with [`es_retain_message()`][erm].
    /// Callers are required to be entitled with `com.apple.developer.endpoint-security.client`. The
    /// application calling this interface must also be approved by users via Transparency, Consent
    /// & Control (TCC) mechanisms using the Privacy Preferences pane and adding the application
    /// to Full Disk Access. When a new client is successfully created, all cached results are
    /// automatically cleared.
    ///
    /// When a new client is initialized, there will be a set of paths and a subset of
    /// `es_event_type_t` events that are automatically muted by default. Generally, most AUTH event
    /// variants are muted but NOTIFY event variants will still be sent to the client. The set of
    /// paths muted by default are ones that can have an extremely negative impact to end users
    /// if their AUTH events are not allowed in a timely manner (for example, executable paths for
    /// processes that are monitored by the watchdogd daemon). It is important to understand that
    /// this list is *not* exhaustive and developers using the EndpointSecurity framework can still
    /// interfere with critical system components and must use caution to limit user impact. The set
    /// of default muted paths and event types may change across macOS releases. It is possible to
    /// both inspect and unmute the set of default muted paths and associated event types using the
    /// appropriate mute-related API, however it is not recommended to unmute these items.
    ///
    /// The only supported way to check if an application is properly TCC authorized for Full Disk
    /// Access is to call `es_new_client()` and handling [`ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED`][not-perm]
    /// in a way appropriate to your application. Most applications will want to ask the user for TCC
    /// authorization when es_new_client returns [`ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED`][not-perm].
    /// To direct the user to the Full Disk Access section in System Settings, applications can use
    /// the following URLs:
    ///
    /// - `x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?Privacy_AllFiles` (macOS 13 and later)
    /// - `x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles` (until macOS 12)
    ///
    /// Applications are advised to use the new URL in macOS 13 as the old one may stop working in a
    /// future release.
    ///
    /// See also:
    ///
    /// - [`es_retain_message()`][erm]
    #[cfg_attr(feature = "macos_11_0_0", doc = "- [`es_release_message()`]")]
    #[cfg_attr(not(feature = "macos_11_0_0"), doc = "- `es_release_message()`")]
    /// - [`es_new_client_result_t`]
    #[cfg_attr(
        feature = "macos_12_0_0",
        doc = "- [`es_muted_paths_events()`]\n- [`es_unmute_path_events()`]"
    )]
    #[cfg_attr(
        not(feature = "macos_12_0_0"),
        doc = "- `es_muted_paths_events()`\n- `es_unmute_path_events()`"
    )]
    ///
    /// [erm]: [es_retain_message]
    /// [not-perm]: crate::es_new_client_result_t::ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED
    #[allow(improper_ctypes)]
    // In this specific case, it is okay because the block is called as
    // an Objc-C block (a closure), it's not modified/dereferenced.
    pub fn es_new_client(client: *mut *mut es_client_t, handler: &es_handler_block_t) -> es_new_client_result_t;

    /// Destroy an `es_client_t`, freeing resources and disconnecting from the ES subsystem
    ///
    /// - `client`: The client to be destroyed
    ///
    /// - `ES_RETURN_SUCCESS` indicates all resources were freed.
    /// - `ES_RETURN_ERROR` indicates an error occured during shutdown and resources were leaked.
    ///
    /// Must be called from the same thread that originally called [`es_new_client()`].
    pub fn es_delete_client(client: *mut es_client_t) -> es_return_t;
}
