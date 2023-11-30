//! Definitions of Endpoint Security events.

use endpoint_sec_sys::{es_event_type_t, es_events_t};

/// Helper macro to define the whole Event enum at once, avoiding endless repetitions of the CFGs
macro_rules! define_event_enum {
    (
        $(#[$enum_meta: meta])*
        pub enum $enum_name: ident from ($raw_ev: ident, $version: ident) {
            $(
                $(#[$b_v_doc: meta])*
                $b_v_const: ident => $b_v_name: ident($b_v_inner: ident [$b_v_var: pat => $b_v_expected_resp_type: expr] {
                    $($b_v_new_name: ident $(: $b_v_new_expr: expr)?,)+
                }),
            )*
            $(
                == #[$v_cfg: meta]
                $(
                    $(#[$v_doc: meta])*
                    $v_const: ident => $v_name: ident($v_inner: ident [$v_var: pat => $v_expected_resp_type: expr] {
                        $($v_new_name: ident $(: $v_new_expr: expr)?,)+
                    }),
                )+
            )*
        }
    ) => {
        $(#[$enum_meta])*
        pub enum $enum_name<'a> {
            $( $(#[$b_v_doc])* $b_v_name($b_v_inner<'a>), )*
            $( $( #[$v_cfg] $(#[$v_doc])* $v_name($v_inner<'a>), )* )*
        }

        ::static_assertions::assert_impl_all!(Event<'_>: Send);

        impl<'a> $enum_name<'a> {
            /// Create an instance from raw parts.
            ///
            /// # Safety
            ///
            /// `event_type`, `raw_event` and `version` must be coming from the same [`crate::message::Message`].
            #[inline(always)]
            pub(crate) unsafe fn from_raw_parts(
                event_type: es_event_type_t,
                $raw_ev: &'a es_events_t,
                $version: u32,
            ) -> Option<Self> {
                // Safety: Safe as we select the union field corresponding to that type and the
                // caller must have respected the calling condition.
                let v = unsafe {
                    match event_type {
                        $( es_event_type_t::$b_v_const => Self::$b_v_name($b_v_inner { $( $b_v_new_name $(: $b_v_new_expr)? ),* }), )*
                        $( $( #[$v_cfg] es_event_type_t::$v_const => Self::$v_name($v_inner { $( $v_new_name $(: $v_new_expr)? ),* }), )* )*
                        _ => return None,
                    }
                };
                Some(v)
            }

            /// For `Auth` events, returns the type of response to use when allowing or denying.
            pub fn expected_response_type(&self) -> Option<ExpectedResponseType> {
                match self {
                    $( Self::$b_v_name($b_v_var) => $b_v_expected_resp_type, )*
                    $( $( #[$v_cfg] Self::$v_name($v_var) => $v_expected_resp_type, )* )*
                }
            }
        }
    };
}

define_event_enum!(
    /// Information related to an event.
    #[derive(Debug, PartialEq, Eq, Hash)]
    pub enum Event from (raw_event, version) {
        /// Authorization request for a process execution.
        ES_EVENT_TYPE_AUTH_EXEC => AuthExec(EventExec [_ => Some(ExpectedResponseType::Auth) ] { raw: &raw_event.exec, version, }),
        /// Authorization request for a file system object being opened.
        ES_EVENT_TYPE_AUTH_OPEN => AuthOpen(EventOpen [e => Some(ExpectedResponseType::Flags { flags: e.fflag() as u32, }) ] { raw: &raw_event.open, }),
        /// Authorization request for a kernel extension being loaded.
        ES_EVENT_TYPE_AUTH_KEXTLOAD => AuthKextLoad(EventKextLoad [_ => Some(ExpectedResponseType::Auth) ] { raw: &raw_event.kextload, }),
        /// Authorization request for a memory map of a file.
        ES_EVENT_TYPE_AUTH_MMAP => AuthMmap(EventMmap [_ => Some(ExpectedResponseType::Auth) ] { raw: &raw_event.mmap, }),
        /// Authorization request for a change of protection for pages.
        ES_EVENT_TYPE_AUTH_MPROTECT => AuthMprotect(EventMprotect [_ => Some(ExpectedResponseType::Auth) ] { raw: &raw_event.mprotect, }),
        /// Authorization request for a file system being mounted.
        ES_EVENT_TYPE_AUTH_MOUNT => AuthMount(EventMount [_ => Some(ExpectedResponseType::Auth) ] { raw: &raw_event.mount, }),
        /// Authorization request for a file system object being renamed.
        ES_EVENT_TYPE_AUTH_RENAME => AuthRename(EventRename [_ => Some(ExpectedResponseType::Auth) ] { raw: &raw_event.rename, }),
        /// Authorization request for a signal being sent to a process.
        ES_EVENT_TYPE_AUTH_SIGNAL => AuthSignal(EventSignal [_ => Some(ExpectedResponseType::Auth) ] { raw: &raw_event.signal, version, }),
        /// Authorization request for a file system object being unlinked.
        ES_EVENT_TYPE_AUTH_UNLINK => AuthUnlink(EventUnlink [_ => Some(ExpectedResponseType::Auth) ] { raw: &raw_event.unlink, }),
        /// Notify a process execution.
        ES_EVENT_TYPE_NOTIFY_EXEC => NotifyExec(EventExec [_ => None ] { raw: &raw_event.exec, version, }),
        /// Notify a file system object being open.
        ES_EVENT_TYPE_NOTIFY_OPEN => NotifyOpen(EventOpen [_ => None ] { raw: &raw_event.open, }),
        /// Notify a new process being forked.
        ES_EVENT_TYPE_NOTIFY_FORK => NotifyFork(EventFork [_ => None ] { raw: &raw_event.fork, version, }),
        /// Notify a new file system object being closed.
        ES_EVENT_TYPE_NOTIFY_CLOSE => NotifyClose(EventClose [_ => None ] { raw: &raw_event.close, version, }),
        /// Notify a file system object being created.
        ES_EVENT_TYPE_NOTIFY_CREATE => NotifyCreate(EventCreate [_ => None ] { raw: &raw_event.create, version, }),
        /// Notify data being atomically exchanged between two files.
        ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA => NotifyExchangeData(EventExchangeData [_ => None ] { raw: &raw_event.exchangedata, }),
        /// Notify a process termination.
        ES_EVENT_TYPE_NOTIFY_EXIT => NotifyExit(EventExit [_ => None ] { raw: &raw_event.exit, }),
        /// Notify a process's task control port event.
        ES_EVENT_TYPE_NOTIFY_GET_TASK => NotifyGetTask(EventGetTask [_ => None ] { raw: &raw_event.get_task, version, }),
        /// Notify a kernel extension being loaded.
        ES_EVENT_TYPE_NOTIFY_KEXTLOAD => NotifyKextLoad(EventKextLoad [_ => None ] { raw: &raw_event.kextload, }),
        /// Notify a kernel extension being unloaded.
        ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD => NotifyKextUnload(EventKextUnload[_ => None ]{ raw: &raw_event.kextunload, }),
        /// Notify a file system object being linked.
        ES_EVENT_TYPE_NOTIFY_LINK => NotifyLink(EventLink[_ => None ]{ raw: &raw_event.link, }),
        /// Notify a memory map of a file.
        ES_EVENT_TYPE_NOTIFY_MMAP => NotifyMmap(EventMmap [_ => None ] { raw: &raw_event.mmap, }),
        /// Notify a change of protection for pages.
        ES_EVENT_TYPE_NOTIFY_MPROTECT => NotifyMprotect(EventMprotect [_ => None ] { raw: &raw_event.mprotect, }),
        /// Notify a file system being mounted.
        ES_EVENT_TYPE_NOTIFY_MOUNT => NotifyMount(EventMount [_ => None ] { raw: &raw_event.mount, }),
        /// Notify a file system being unmounted.
        ES_EVENT_TYPE_NOTIFY_UNMOUNT => NotifyUnmount(EventUnmount [_ => None ] { raw: &raw_event.unmount, }),
        /// Notify a connection being opened to an I/O Kit IOService.
        ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN => NotifyIoKitOpen(EventIoKitOpen [_ => None ] { raw: &raw_event.iokit_open, }),
        /// Notify a file system object being renamed.
        ES_EVENT_TYPE_NOTIFY_RENAME => NotifyRename(EventRename [_ => None ] { raw: &raw_event.rename, }),
        /// Notify when file system attributes are being modified.
        ES_EVENT_TYPE_NOTIFY_SETATTRLIST => NotifySetAttrlist(EventSetAttrlist [_ => None ] { raw: &raw_event.setattrlist, }),
        /// Notify when extended attribute are being set.
        ES_EVENT_TYPE_NOTIFY_SETEXTATTR => NotifySetExtAttr(EventSetExtAttr[_ => None ]{ raw: &raw_event.setextattr, }),
        /// Notify when a file system object flags are being modified.
        ES_EVENT_TYPE_NOTIFY_SETFLAGS => NotifySetFlags(EventSetFlags [_ => None ] { raw: &raw_event.setflags, }),
        /// Notify when a file system object mode is being modified.
        ES_EVENT_TYPE_NOTIFY_SETMODE => NotifySetMode(EventSetMode [_ => None ] { raw: &raw_event.setmode, }),
        /// Notify when a file system object owner is being modified.
        ES_EVENT_TYPE_NOTIFY_SETOWNER => NotifySetOwner(EventSetOwner [_ => None ] { raw: &raw_event.setowner, }),
        /// Notify a signal being sent to a process.
        ES_EVENT_TYPE_NOTIFY_SIGNAL => NotifySignal(EventSignal [_ => None ] { raw: &raw_event.signal, version, }),
        /// Notify a file system object being unlinked.
        ES_EVENT_TYPE_NOTIFY_UNLINK => NotifyUnlink(EventUnlink [_ => None ] { raw: &raw_event.unlink, }),
        /// Notify a write to a file.
        ES_EVENT_TYPE_NOTIFY_WRITE => NotifyWrite(EventWrite [_ => None ] { raw: &raw_event.write, }),
        /// Authorization request for a file being materialize via the FileProvider framework.
        ES_EVENT_TYPE_AUTH_FILE_PROVIDER_MATERIALIZE => AuthFileProviderMaterialize( EventFileProviderMaterialize [_ => Some(ExpectedResponseType::Auth) ] { raw: &raw_event.file_provider_materialize, version, } ),
        /// Notify a file being materialize via the FileProvider framework.
        ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_MATERIALIZE => NotifyFileProviderMaterialize(EventFileProviderMaterialize [_ => None ] { raw: &raw_event.file_provider_materialize, version, }),
        /// Authorization request for file contents being updated via the FileProvider framework.
        ES_EVENT_TYPE_AUTH_FILE_PROVIDER_UPDATE => AuthFileProviderUpdate( EventFileProviderUpdate [_ => Some(ExpectedResponseType::Auth) ] { raw: &raw_event.file_provider_update, } ),
        /// Notify a file contents being updated via the FileProvider framework.
        ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_UPDATE => NotifyFileProviderUpdate( EventFileProviderUpdate [_ => None ] { raw: &raw_event.file_provider_update, } ),
        /// Authorization request for a symbolic link being resolved.
        ES_EVENT_TYPE_AUTH_READLINK => AuthReadLink(EventReadLink [_ => Some(ExpectedResponseType::Auth) ] { raw: &raw_event.readlink, }),
        /// Notify a symbolic link being resolved.
        ES_EVENT_TYPE_NOTIFY_READLINK => NotifyReadLink(EventReadLink [_ => None ] { raw: &raw_event.readlink, }),
        /// Authorization request for a file being truncated.
        ES_EVENT_TYPE_AUTH_TRUNCATE => AuthTruncate(EventTruncate [_ => Some(ExpectedResponseType::Auth) ] { raw: &raw_event.truncate, }),
        /// Notify a file being truncated.
        ES_EVENT_TYPE_NOTIFY_TRUNCATE => NotifyTruncate(EventTruncate [_ => None ] { raw: &raw_event.truncate, }),
        /// Authorization request for a file system object being linked.
        ES_EVENT_TYPE_AUTH_LINK => AuthLink(EventLink[_ => Some(ExpectedResponseType::Auth) ]{ raw: &raw_event.link, }),
        /// Notify a file system object being lookup.
        ES_EVENT_TYPE_NOTIFY_LOOKUP => NotifyLookup(EventLookup [_ => None ] { raw: &raw_event.lookup, }),
        /// Authorization request for a file system object being created.
        ES_EVENT_TYPE_AUTH_CREATE => AuthCreate(EventCreate [_ => Some(ExpectedResponseType::Auth) ] { raw: &raw_event.create, version, }),
        /// Authorization request for file system attributes being modified.
        ES_EVENT_TYPE_AUTH_SETATTRLIST => AuthSetAttrlist(EventSetAttrlist [_ => Some(ExpectedResponseType::Auth) ] { raw: &raw_event.setattrlist, }),
        /// Authorization request for an extended attribute being set.
        ES_EVENT_TYPE_AUTH_SETEXTATTR => AuthSetExtAttr(EventSetExtAttr [_ => Some(ExpectedResponseType::Auth) ] { raw: &raw_event.setextattr, }),
        /// Authorization request for a file system object flags being modified.
        ES_EVENT_TYPE_AUTH_SETFLAGS => AuthSetFlags(EventSetFlags [_ => Some(ExpectedResponseType::Auth) ] { raw: &raw_event.setflags, }),
        /// Authorization request for a file system object mode being modified.
        ES_EVENT_TYPE_AUTH_SETMODE => AuthSetMode(EventSetMode [_ => Some(ExpectedResponseType::Auth) ] { raw: &raw_event.setmode, }),
        /// Authorization request for a file system object owner being modified.
        ES_EVENT_TYPE_AUTH_SETOWNER => AuthSetOwner(EventSetOwner [_ => Some(ExpectedResponseType::Auth) ] { raw: &raw_event.setowner, }),

        == #[cfg(feature = "macos_10_15_1")]
        /// Authorization request for when the current working directory of a process is being changed.
        ES_EVENT_TYPE_AUTH_CHDIR => AuthChdir(EventChdir [_ => Some(ExpectedResponseType::Auth) ] { raw: &raw_event.chdir, }),
        /// Notify when the current working directory change for a process.
        ES_EVENT_TYPE_NOTIFY_CHDIR => NotifyChdir(EventChdir [_ => None ] { raw: &raw_event.chdir, }),
        /// Authorization request for file system attributes being retrieved.
        ES_EVENT_TYPE_AUTH_GETATTRLIST => AuthGetAttrlist(EventGetAttrlist [_ => Some(ExpectedResponseType::Auth) ] { raw: &raw_event.getattrlist, }),
        /// Notify when file system attributes are being retrieved.
        ES_EVENT_TYPE_NOTIFY_GETATTRLIST => NotifyGetAttrlist(EventGetAttrlist [_ => None ] { raw: &raw_event.getattrlist, }),
        /// Notify when a file is being stat.
        ES_EVENT_TYPE_NOTIFY_STAT => NotifyStat(EventStat [_ => None ] { raw: &raw_event.stat, }),
        /// Notify when a file access test is performed.
        ES_EVENT_TYPE_NOTIFY_ACCESS => NotifyAccess(EventAccess [_ => None ] { raw: &raw_event.access, }),
        /// Authorization request for a chroot.
        ES_EVENT_TYPE_AUTH_CHROOT => AuthChroot(EventChroot [_ => Some(ExpectedResponseType::Auth) ] { raw: &raw_event.chroot, }),
        /// Notify when a chroot is performed.
        ES_EVENT_TYPE_NOTIFY_CHROOT => NotifyChroot(EventChroot [_ => None ] { raw: &raw_event.chroot, }),
        /// Authorization request for a file access and modification times change.
        ES_EVENT_TYPE_AUTH_UTIMES => AuthUTimes(EventUTimes [_ => Some(ExpectedResponseType::Auth) ] { raw: &raw_event.utimes, }),
        /// Notify when a file access and modification times changed.
        ES_EVENT_TYPE_NOTIFY_UTIMES => NotifyUTimes(EventUTimes [_ => None ] { raw: &raw_event.utimes, }),
        /// Authorization request for a file being cloned.
        ES_EVENT_TYPE_AUTH_CLONE => AuthClone(EventClone [_ => Some(ExpectedResponseType::Auth) ] { raw: &raw_event.clone, }),
        /// Notify for a file being cloned.
        ES_EVENT_TYPE_NOTIFY_CLONE => NotifyClone(EventClone [_ => None ] { raw: &raw_event.clone, }),
        /// Notify for a file control event.
        ES_EVENT_TYPE_NOTIFY_FCNTL => NotifyFcntl(EventFcntl [_ => None ] { raw: &raw_event.fcntl, }),
        /// Authorization request for extended attribute being retrieved.
        ES_EVENT_TYPE_AUTH_GETEXTATTR => AuthGetExtAttr(EventGetExtAttr [_ => Some(ExpectedResponseType::Auth) ] { raw: &raw_event.getextattr, }),
        /// Notify when extended attribute are being retrieved.
        ES_EVENT_TYPE_NOTIFY_GETEXTATTR => NotifyGetExtAttr(EventGetExtAttr[_ => None ]{ raw: &raw_event.getextattr, }),
        /// Authorization request for extended attributes being listed.
        ES_EVENT_TYPE_AUTH_LISTEXTATTR => AuthListExtAttr(EventListExtAttr [_ => Some(ExpectedResponseType::Auth) ] { raw: &raw_event.listextattr, }),
        /// Notify when extended attributes are being listed.
        ES_EVENT_TYPE_NOTIFY_LISTEXTATTR => NotifyListExtAttr(EventListExtAttr [_ => None ] { raw: &raw_event.listextattr , }),
        /// Authorization request for directory entries being read.
        ES_EVENT_TYPE_AUTH_READDIR => AuthReadDir(EventReadDir [_ => Some(ExpectedResponseType::Auth) ] { raw: &raw_event.readdir, }),
        /// Notify when directory entries are being read.
        ES_EVENT_TYPE_NOTIFY_READDIR => NotifyReadDir(EventReadDir [_ => None ] { raw: &raw_event.readdir, }),
        /// Authorization request for an extended attribute being deleted.
        ES_EVENT_TYPE_AUTH_DELETEEXTATTR => AuthDeleteExtAttr(EventDeleteExtAttr [_ => Some(ExpectedResponseType::Auth) ] { raw: &raw_event.deleteextattr , }),
        /// Notify when an extended attribute are being deleted.
        ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR => NotifyDeleteExtAttr( EventDeleteExtAttr [_ => None ] { raw: &raw_event.deleteextattr, } ),
        /// Authorization request for a file system path being retrieved based on FSID.
        ES_EVENT_TYPE_AUTH_FSGETPATH => AuthFsGetPath(EventFsGetPath [_ => Some(ExpectedResponseType::Auth) ] { raw: &raw_event.fsgetpath, }),
        /// Notify when a file system path is retrieved based on FSID.
        ES_EVENT_TYPE_NOTIFY_FSGETPATH => NotifyFsGetPath(EventFsGetPath [_ => None ] { raw: &raw_event.fsgetpath, }),
        /// Notify when a file descriptor is being duplicated.
        ES_EVENT_TYPE_NOTIFY_DUP => NotifyDup(EventDup [_ => None ] { raw: &raw_event.dup, }),
        /// Authorization request for the system time being modified.
        ES_EVENT_TYPE_AUTH_SETTIME => AuthSetTime(EventSetTime [_ => Some(ExpectedResponseType::Auth) ] { raw: &raw_event.settime, }),
        /// Notify the system time being modified.
        ES_EVENT_TYPE_NOTIFY_SETTIME => NotifySetTime(EventSetTime [_ => None ] { raw: &raw_event.settime, }),
        /// Notify a UNIX-domain socket is about to be bound to a path.
        ES_EVENT_TYPE_NOTIFY_UIPC_BIND => NotifyUipcBind(EventUipcBind [_ => None ] { raw: &raw_event.uipc_bind, }),
        /// Authorization request to bind a UNIX-domain socket to a path.
        ES_EVENT_TYPE_AUTH_UIPC_BIND => AuthUipcBind(EventUipcBind [_ => Some(ExpectedResponseType::Auth) ] { raw: &raw_event.uipc_bind, }),
        /// Notify a UNIX-domain socket is about to be connected.
        ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT => NotifyUipcConnect(EventUipcConnect [_ => None ] { raw: &raw_event.uipc_connect , }),
        /// Authorization request to connect a UNIX-domain socket.
        ES_EVENT_TYPE_AUTH_UIPC_CONNECT => AuthUipcConnect(EventUipcConnect[_ => Some(ExpectedResponseType::Auth) ]{ raw: &raw_event.uipc_connect, }),
        /// Authorization request for data being atomically exchanged between two files.
        ES_EVENT_TYPE_AUTH_EXCHANGEDATA => AuthExchangeData(EventExchangeData [_ => Some(ExpectedResponseType::Auth) ] { raw: &raw_event.exchangedata , }),
        /// Authorization request to set a file's ACL.
        ES_EVENT_TYPE_AUTH_SETACL => AuthSetAcl(EventSetAcl [_ => Some(ExpectedResponseType::Auth) ] { raw: &raw_event.setacl, }),
        /// Notify a file's ACL was set.
        ES_EVENT_TYPE_NOTIFY_SETACL => NotifySetAcl(EventSetAcl [_ => None ] { raw: &raw_event.setacl, }),

        == #[cfg(feature = "macos_10_15_4")]
        /// Notify a pseudoterminal control device was granted.
        ES_EVENT_TYPE_NOTIFY_PTY_GRANT => NotifyPtyGrant(EventPtyGrant [_ => None ] { raw: &raw_event.pty_grant, }),
        /// Notify a pseudoterminal control device was closed.
        ES_EVENT_TYPE_NOTIFY_PTY_CLOSE => NotifyPtyClose(EventPtyClose [_ => None ] { raw: &raw_event.pty_close, }),
        /// Authorization request for retrieving process information.
        ES_EVENT_TYPE_AUTH_PROC_CHECK => AuthProcCheck(EventProcCheck [_ => Some(ExpectedResponseType::Auth) ] { raw: &raw_event.proc_check, version, }),
        /// Notify about retrieval of process information.
        ES_EVENT_TYPE_NOTIFY_PROC_CHECK => NotifyProcCheck(EventProcCheck [_ => None ] { raw: &raw_event.proc_check, version, }),
        /// Authorization request for a process's task control port event.
        ES_EVENT_TYPE_AUTH_GET_TASK => AuthGetTask(EventGetTask [_ => Some(ExpectedResponseType::Auth) ] { raw: &raw_event.get_task, version, }),

        == #[cfg(feature = "macos_11_0_0")]
        /// Authorization request for an access control check being performed when searching a volume or mounted filesystem.
        ES_EVENT_TYPE_AUTH_SEARCHFS => AuthSearchFs(EventSearchFs [_ => Some(ExpectedResponseType::Auth) ] { raw: &raw_event.searchfs, }),
        /// Notify for an access control check performed when searching a volume or mounted filesystem.
        ES_EVENT_TYPE_NOTIFY_SEARCHFS => NotifySearchFs(EventSearchFs [_ => None ] { raw: &raw_event.searchfs, }),
        /// Authorization request for a file control.
        ES_EVENT_TYPE_AUTH_FCNTL => AuthFcntl(EventFcntl [_ => Some(ExpectedResponseType::Auth) ] { raw: &raw_event.fcntl, }),
        /// Authorization request for a connection being opened to an I/O Kit IOService.
        ES_EVENT_TYPE_AUTH_IOKIT_OPEN => AuthIoKitOpen(EventIoKitOpen [_ => Some(ExpectedResponseType::Auth) ] { raw: &raw_event.iokit_open, }),
        /// Authorization request for one of `pid_suspend()`, `pid_resume()` or `pid_shutdown_sockets()` to be called
        ES_EVENT_TYPE_AUTH_PROC_SUSPEND_RESUME => AuthProcSuspendResume( EventProcSuspendResume [_ => Some(ExpectedResponseType::Auth) ] { raw: &raw_event.proc_suspend_resume, version, } ),
        /// called on a process.
        ES_EVENT_TYPE_NOTIFY_PROC_SUSPEND_RESUME => NotifyProcSuspendResume( EventProcSuspendResume [_ => None ] { raw: &raw_event.proc_suspend_resume, version, } ),
        /// Notify for one of `pid_suspend()`, `pid_resume()` or `pid_shutdown_sockets()` is being
        ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED => NotifyCSInvalidated( EventCSInvalidated [_ => None ] { raw: &raw_event.cs_invalidated, } ),
        /// called on a process.
        ES_EVENT_TYPE_NOTIFY_GET_TASK_NAME => NotifyGetTaskName(EventGetTaskName [_ => None ] { raw: &raw_event.get_task_name, version, }),
        /// Notify for a code signing status for a process being invalidated.
        ES_EVENT_TYPE_NOTIFY_TRACE => NotifyTrace(EventTrace [_ => None ] { raw: &raw_event.trace, version, }),
        /// Notify for the recuperation of a process's task name port.
        ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE => NotifyRemoteThreadCreate( EventRemoteThreadCreate [_ => None ] { raw: &raw_event.remote_thread_create, version, } ),
        /// Notify for an attempt to attach another process.
        ES_EVENT_TYPE_AUTH_REMOUNT => AuthRemount(EventRemount [_ => Some(ExpectedResponseType::Auth) ] { raw: &raw_event.remount, }),
        /// Notify a process has attempted to create a thread in another process.
        ES_EVENT_TYPE_NOTIFY_REMOUNT => NotifyRemount(EventRemount [_ => None ] { raw: &raw_event.remount, }),

        == #[cfg(feature = "macos_11_3_0")]
        /// Authorization request for a file system being remounted.
        ES_EVENT_TYPE_AUTH_GET_TASK_READ => AuthGetTaskRead(EventGetTaskRead [_ => Some(ExpectedResponseType::Auth) ] { raw: &raw_event.get_task_read, version, }),
        /// Notify a file system being remounted.
        ES_EVENT_TYPE_NOTIFY_GET_TASK_READ => NotifyGetTaskRead(EventGetTaskRead [_ => None ] { raw: &raw_event.get_task_read, version, }),
        /// Authorization request for the recuperation of a process's task read port.
        ES_EVENT_TYPE_NOTIFY_GET_TASK_INSPECT => NotifyGetTaskInspect(EventGetTaskInspect [_ => None ]{ raw: &raw_event.get_task_inspect, version, }),

        == #[cfg(feature = "macos_12_0_0")]
        /// Notify for the recuperation of a process's task read port.
        ES_EVENT_TYPE_NOTIFY_SETUID => NotifySetuid(EventSetuid [_ => None ] { raw: &raw_event.setuid, }),
        /// Notify for the recuperation of a process's task inspect port.
        ES_EVENT_TYPE_NOTIFY_SETGID => NotifySetgid(EventSetgid [_ => None ] { raw: &raw_event.setgid, }),
        /// Notify a process has called `setuid()`.
        ES_EVENT_TYPE_NOTIFY_SETEUID => NotifySeteuid(EventSeteuid [_ => None ] { raw: &raw_event.seteuid, }),
        /// Notify a process has called `setgid()`.
        ES_EVENT_TYPE_NOTIFY_SETEGID => NotifySetegid(EventSetegid [_ => None ] { raw: &raw_event.setegid, }),
        /// Notify a process has called `seteuid()`.
        ES_EVENT_TYPE_NOTIFY_SETREUID => NotifySetreuid(EventSetreuid [_ => None ] { raw: &raw_event.setreuid, }),
        /// Notify a process has called `setegid()`.
        ES_EVENT_TYPE_NOTIFY_SETREGID => NotifySetregid(EventSetregid [_ => None ] { raw: &raw_event.setregid, }),
        /// Notify a process has called `setreuid()`.
        ES_EVENT_TYPE_AUTH_COPYFILE => AuthCopyFile(EventCopyFile [_ => Some(ExpectedResponseType::Auth) ] { raw: &raw_event.copyfile, }),
        /// Notify a process has called `setregid()`.
        ES_EVENT_TYPE_NOTIFY_COPYFILE => NotifyCopyFile(EventCopyFile [_ => None ] { raw: &raw_event.copyfile, }),

        == #[cfg(feature = "macos_13_0_0")]
        /// Notify an authentication was performed.
        ES_EVENT_TYPE_NOTIFY_AUTHENTICATION => NotifyAuthentication(EventAuthentication [_ => None] { raw: raw_event.authentication.as_opt()?, version, }),
        /// Notify that XProtect detected malware.
        ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED => NotifyXpMalwareDetected(EventXpMalwareDetected [_ => None] { raw: raw_event.xp_malware_detected.as_opt()?, }),
        /// Notify that XProtect remediated malware.
        ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED => NotifyXpMalwareRemediated(EventXpMalwareRemediated [_ => None] { raw: raw_event.xp_malware_remediated.as_opt()?, }),
        /// Notify that LoginWindow has logged in a user.
        ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN => NotifyLwSessionLogin(EventLwSessionLogin [_ => None] { raw: raw_event.lw_session_login.as_opt()?, }),
        /// Notify that LoginWindow has logged out a user.
        ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGOUT => NotifyLwSessionLogout(EventLwSessionLogout [_ => None] { raw: raw_event.lw_session_logout.as_opt()?, }),
        /// Notify that LoginWindow locked the screen of a session.
        ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOCK => NotifyLwSessionLock(EventLwSessionLock [_ => None] { raw: raw_event.lw_session_lock.as_opt()?, }),
        /// Notify that LoginWindow unlocked the screen of a session.
        ES_EVENT_TYPE_NOTIFY_LW_SESSION_UNLOCK => NotifyLwSessionUnlock(EventLwSessionUnlock [_ => None] { raw: raw_event.lw_session_unlock.as_opt()?, }),
        /// that Screen Sharing has attached to a graphical session.
        ES_EVENT_TYPE_NOTIFY_SCREENSHARING_ATTACH => NotifyScreensharingAttach(EventScreensharingAttach [_ => None] { raw: raw_event.screensharing_attach.as_opt()?, }),
        /// Notify that Screen Sharing has detached from a graphical session.
        ES_EVENT_TYPE_NOTIFY_SCREENSHARING_DETACH => NotifyScreensharingDetach(EventScreensharingDetach [_ => None] { raw: raw_event.screensharing_detach.as_opt()?, }),
        /// Notify about an OpenSSH login event.
        ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN => NotifyOpensshLogin(EventOpensshLogin [_ => None] { raw: raw_event.openssh_login.as_opt()?, }),
        /// Notify about an OpenSSH logout event.
        ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT => NotifyOpensshLogout(EventOpensshLogout [_ => None] { raw: raw_event.openssh_logout.as_opt()?, }),
        /// Notify about an authenticated login event from `/usr/bin/login`.
        ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN => NotifyLoginLogin(EventLoginLogin [_ => None] { raw: raw_event.login_login.as_opt()?, }),
        /// Notify about an authenticated logout event from `/usr/bin/login`.
        ES_EVENT_TYPE_NOTIFY_LOGIN_LOGOUT => NotifyLoginLogout(EventLoginLogout [_ => None] { raw: raw_event.login_logout.as_opt()?, }),
        /// Notify for a launch item being made known to background task management.
        ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD => NotifyBtmLaunchItemAdd(EventBtmLaunchItemAdd [_ => None] { raw: raw_event.btm_launch_item_add.as_opt()?, version, }),
        /// Notify for a launch item being removed from background task management.
        ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE => NotifyBtmLaunchItemRemove(EventBtmLaunchItemRemove [_ => None] { raw: raw_event.btm_launch_item_remove.as_opt()?, version, }),

        == #[cfg(feature = "macos_14_0_0")]
        /// Notify about Profiles installed on the system.
        ES_EVENT_TYPE_NOTIFY_PROFILE_ADD => NotifyProfileAdd (EventProfileAdd [_ => None] { raw: raw_event.profile_add.as_opt()?, version, }),
        /// Notify about Profiles removed on the system.
        ES_EVENT_TYPE_NOTIFY_PROFILE_REMOVE => NotifyProfileRemove (EventProfileRemove [_ => None] { raw: raw_event.profile_remove.as_opt()?, version, }),
        /// Notify about a su policy decisions event.
        ES_EVENT_TYPE_NOTIFY_SU => NotifySu(EventSu [_ => None] { raw: raw_event.su.as_opt()?, }),
        /// Notify about a process petitioned for certain authorization rights.
        ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_PETITION => NotifyAuthorizationPetition (EventAuthorizationPetition [_ => None] { raw: raw_event.authorization_petition.as_opt()?, version, }),
        /// Notification that a process had it's right petition judged
        ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_JUDGEMENT => NotifyAuthorizationJudgement (EventAuthorizationJudgement [_ => None] { raw: raw_event.authorization_judgement.as_opt()?, version, }),
    }
);

/// Type of response function to use for this event.
///
/// - [`Client::respond_auth_result()`][crate::Client::respond_auth_result]
/// - [`Client::respond_flags_result()`][crate::Client::respond_flags_result]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum ExpectedResponseType {
    /// Respond with [`Client::respond_auth_result()`][crate::Client::respond_auth_result]
    Auth,
    /// Respond with [`Client::respond_flags_result()`][crate::Client::respond_flags_result]
    Flags {
        /// Flags used by the original event
        flags: u32,
    },
}

/// Generate an iterator implementation for an array component of an event.
///
/// Safety:
///
/// - `raw_element_func` will be called like this: `raw_element_func(&raw_es_event, valid index)`,
///   it must be safe to call under these conditions.
/// - `raw_to_wrapped` will be called with the result of the preceding operation like this:
///   `raw_to_wrapped(raw_token)`. This token COULD be null if `raw_element_func` can return `null`
///   when called in the conditions described above. Usually Apple documents that if the event is
///   a valid pointer and the index is correct, the function cannot return `null` and that calling
///   outside the bounds is undefined behaviour.
macro_rules! make_event_data_iterator {
    ($wrapped_event: ident; $(#[$enum_doc:meta])+ $name:ident with $element_count: ident ($count_ty: ty); $item: ty; $raw_element_func: ident, $raw_to_wrapped: path$(,)?) => {
        $(#[$enum_doc])*
        pub struct $name<'event, 'raw> {
            /// Wrapped event
            ev: &'event $wrapped_event<'raw>,
            /// Element count. When `current >= count`, the iterator is done and will only return
            /// `None` for all subsequent calls to `next`.
            count: $count_ty,
            /// A call to `next` will yield element `current`
            current: $count_ty,
        }

        impl $name<'_, '_> {
            /// New iterator from event
            fn new<'ev, 'raw>(ev: &'ev $wrapped_event<'raw>) -> $name<'ev, 'raw> {
                $name {
                    ev,
                    count: ev.$element_count(),
                    current: 0,
                }
            }
        }

        impl<'raw> std::iter::Iterator for $name<'_, 'raw> {
            type Item = $item;

            fn next(&mut self) -> Option<Self::Item> {
                if self.current < self.count {
                    // Safety: Safe as raw is a reference and therefore cannot be null
                    let raw_token = unsafe { $raw_element_func(self.ev.raw, self.current) };

                    self.current = self.current.saturating_add(1);
                    // Safety: Safe as we ensure the lifetime is rebound correctly in our wrappers
                    Some(unsafe { $raw_to_wrapped(raw_token) })
                } else {
                    None
                }
            }

            #[inline(always)]
            fn nth(&mut self, n: usize) -> Option<Self::Item> {
                self.current = n.min(<$count_ty>::MAX as usize) as $count_ty;
                self.next()
            }

            #[inline(always)]
            fn last(mut self) -> Option<Self::Item>
            where
                Self: Sized,
            {
                self.current = self.count.saturating_sub(1);
                self.next()
            }

            #[inline(always)]
            fn size_hint(&self) -> (usize, Option<usize>) {
                let len = self.len();
                (len, Some(len))
            }

            #[inline(always)]
            fn count(mut self) -> usize {
                let len = self.len();
                self.current = self.count;
                len
            }
        }

        impl std::iter::ExactSizeIterator for $name<'_, '_> {
            #[inline(always)]
            fn len(&self) -> usize {
                // Casting to usize if ok: all macOS machines are 64 bits now so a u32 will always
                // fit into a usize
                self.count.saturating_sub(self.current) as usize
            }
        }

        impl std::iter::FusedIterator for $name<'_, '_> {}
    };
}

/// Wrapper for the `.as_ref()` call on `es_string_token_t` with lifetime extension.
///
/// # Safety
///
/// This is a horrible horrible hack. Apple documents that the `es_string_token_t` returned by
/// both [`es_exec_env`] and [`es_exec_arg`] are zero-allocation when in bounds and that the
/// returned string token must not outlive the original event, which it cannot do in our
/// iterator so it's safe. Thanks Rust for references and the borrow checker.
unsafe fn as_os_str<'a>(x: endpoint_sec_sys::es_string_token_t) -> &'a std::ffi::OsStr {
    // Safety: this is only called inside the iterator where `'a` will be the lifetime of `&mut self`
    unsafe { &*(x.as_os_str() as *const _) }
}

/// Helper macro to define the event modules without copying the cfgs dozens of times.
macro_rules! cfg_mod {
    (
        $( mod $b_name: ident; )*
        $(
            == #[$cfg: meta];
            $( mod $name: ident; )+
        )*
    ) => {
        $( mod $b_name; pub use $b_name::*; )*
        $( $( #[$cfg] mod $name; #[$cfg] pub use $name::*; )+ )*
    };
}

cfg_mod! {
    mod event_close;
    mod event_create;
    mod event_exchangedata;
    mod event_exec;
    mod event_exit;
    mod event_file_provider_materialize;
    mod event_file_provider_update;
    mod event_fork;
    mod event_get_task;
    mod event_iokit_open;
    mod event_kextload;
    mod event_kextunload;
    mod event_link;
    mod event_lookup;
    mod event_mmap;
    mod event_mount;
    mod event_mprotect;
    mod event_open;
    mod event_read_link;
    mod event_rename;
    mod event_setattrlist;
    mod event_setextattr;
    mod event_setflags;
    mod event_setmode;
    mod event_setowner;
    mod event_signal;
    mod event_truncate;
    mod event_unlink;
    mod event_unmount;
    mod event_write;

    == #[cfg(feature = "macos_10_15_1")];
    mod event_access;
    mod event_chdir;
    mod event_chroot;
    mod event_clone;
    mod event_deleteextattr;
    mod event_dup;
    mod event_fcntl;
    mod event_fsgetpath;
    mod event_getattrlist;
    mod event_getextattr;
    mod event_listextattr;
    mod event_readdir;
    mod event_setacl;
    mod event_settime;
    mod event_stat;
    mod event_uipc_bind;
    mod event_uipc_connect;
    mod event_utimes;

    == #[cfg(feature = "macos_10_15_4")];
    mod event_pty_grant;
    mod event_proc_check;
    mod event_pty_close;

    == #[cfg(feature = "macos_11_0_0")];
    mod event_cs_invalidated;
    mod event_get_task_name;
    mod event_proc_suspend_resume;
    mod event_remote_thread_create;
    mod event_remount;
    mod event_searchfs;
    mod event_trace;

    == #[cfg(feature = "macos_11_3_0")];
    mod event_get_task_inspect;
    mod event_get_task_read;

    == #[cfg(feature = "macos_12_0_0")];
    mod event_copyfile;
    mod event_setegid;
    mod event_seteuid;
    mod event_setgid;
    mod event_setregid;
    mod event_setreuid;
    mod event_setuid;

    == #[cfg(feature = "macos_13_0_0")];
    mod event_authentication;
    mod event_xp_malware_detected;
    mod event_xp_malware_remediated;
    mod event_lw_session_login;
    mod event_lw_session_logout;
    mod event_lw_session_lock;
    mod event_lw_session_unlock;
    mod event_screesharing_attach;
    mod event_screesharing_detach;
    mod event_openssh_login;
    mod event_openssh_logout;
    mod event_login_login;
    mod event_login_logout;
    mod event_btm_launch_item_add;
    mod event_btm_launch_item_remove;

    == #[cfg(feature = "macos_14_0_0")];
    mod event_profile_add;
    mod event_profile_remove;
    mod event_su;
    mod event_authorization_petition;
    mod event_authorization_judgement;
}
