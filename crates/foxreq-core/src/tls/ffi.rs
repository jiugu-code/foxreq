#![allow(unsafe_code)]

use std::{
    ffi::c_char,
    mem::size_of,
    ptr::{self, NonNull},
    slice,
};

pub(super) const ABI_VERSION: u32 = 1;
pub(super) const RESULT_OK: u32 = 0;
pub(super) const RESULT_INVALID_ARGUMENT: u32 = 1;
pub(super) const RESULT_STATE: u32 = 3;
pub(super) const RESULT_BUFFER_TOO_SMALL: u32 = 9;
pub(super) const RESULT_END_OF_STREAM: u32 = 10;

const STUB_OPERATION_READ: u32 = 1;
const STUB_OPERATION_WRITE: u32 = 2;
const STUB_OPERATION_CLOSE: u32 = 3;

#[repr(C)]
pub(super) struct RawRuntime {
    _private: [u8; 0],
}

#[repr(C)]
pub(super) struct RawSessionCache {
    _private: [u8; 0],
}

#[repr(C)]
pub(super) struct RawConnection {
    _private: [u8; 0],
}

#[repr(C)]
struct RawBuffer {
    _private: [u8; 0],
}

#[repr(C)]
struct RawSlice {
    data: *const u8,
    length: u64,
}

#[repr(C)]
struct RawRuntimeOptions {
    struct_size: u32,
    abi_version: u32,
    reserved: u64,
}

#[repr(C)]
struct RawSessionCacheOptions {
    struct_size: u32,
    abi_version: u32,
    capacity: u32,
    reserved: u32,
}

#[repr(C)]
struct RawConnectOptions {
    struct_size: u32,
    abi_version: u32,
    host: RawSlice,
    port: u16,
    reserved16: u16,
    verification_mode: u32,
    timeout_millis: u64,
    profile_id: RawSlice,
    alpn_wire: RawSlice,
    session_cache: *mut RawSessionCache,
    reserved: [u64; 2],
}

#[repr(C)]
struct RawCertificateResult {
    struct_size: u32,
    abi_version: u32,
    verification_performed: u32,
    verified: u32,
    category: u32,
    nss_code: i32,
    nspr_code: i32,
    reserved32: u32,
}

#[repr(C)]
struct RawErrorInfo {
    struct_size: u32,
    abi_version: u32,
    category: u32,
    reserved32: u32,
    nss_code: i32,
    nspr_code: i32,
    auxiliary: u64,
}

#[link(name = "foxreq_nss", kind = "static")]
unsafe extern "C" {
    #[link_name = "foxreq_nss_abi_version"]
    fn raw_abi_version() -> u32;
    #[link_name = "foxreq_nss_runtime_create"]
    fn raw_runtime_create(
        options: *const RawRuntimeOptions,
        out_runtime: *mut *mut RawRuntime,
    ) -> u32;
    #[link_name = "foxreq_nss_runtime_free"]
    fn raw_runtime_free(runtime: *mut RawRuntime);
    #[link_name = "foxreq_nss_session_cache_create"]
    fn raw_session_cache_create(
        runtime: *mut RawRuntime,
        options: *const RawSessionCacheOptions,
        out_cache: *mut *mut RawSessionCache,
    ) -> u32;
    #[link_name = "foxreq_nss_session_cache_free"]
    fn raw_session_cache_free(cache: *mut RawSessionCache);
    #[link_name = "foxreq_nss_connect"]
    fn raw_connect(
        runtime: *mut RawRuntime,
        options: *const RawConnectOptions,
        out_connection: *mut *mut RawConnection,
    ) -> u32;
    #[link_name = "foxreq_nss_connection_free"]
    fn raw_connection_free(connection: *mut RawConnection);
    #[link_name = "foxreq_nss_connection_negotiated_alpn"]
    fn raw_negotiated_alpn(connection: *mut RawConnection, out_buffer: *mut *mut RawBuffer) -> u32;
    #[link_name = "foxreq_nss_connection_certificate_result"]
    fn raw_certificate_result(
        connection: *mut RawConnection,
        out_result: *mut RawCertificateResult,
    ) -> u32;
    #[link_name = "foxreq_nss_connection_read"]
    fn raw_read(
        connection: *mut RawConnection,
        destination: *mut u8,
        capacity: u64,
        timeout_millis: u64,
        out_read: *mut u64,
    ) -> u32;
    #[link_name = "foxreq_nss_connection_write"]
    fn raw_write(
        connection: *mut RawConnection,
        source: *const u8,
        length: u64,
        timeout_millis: u64,
        out_written: *mut u64,
    ) -> u32;
    #[link_name = "foxreq_nss_connection_close"]
    fn raw_close(connection: *mut RawConnection, timeout_millis: u64) -> u32;
    #[link_name = "foxreq_nss_connection_last_error"]
    fn raw_last_error(
        connection: *mut RawConnection,
        out_error: *mut RawErrorInfo,
        message: *mut c_char,
        message_capacity: u64,
        out_required: *mut u64,
    ) -> u32;
    #[link_name = "foxreq_nss_buffer_view"]
    fn raw_buffer_view(
        buffer: *const RawBuffer,
        out_data: *mut *const u8,
        out_length: *mut u64,
    ) -> u32;
    #[link_name = "foxreq_nss_buffer_free"]
    fn raw_buffer_free(buffer: *mut RawBuffer);
    #[link_name = "foxreq_nss_stub_set_read_data"]
    fn raw_stub_set_read_data(connection: *mut RawConnection, data: *const u8, length: u64) -> u32;
    #[link_name = "foxreq_nss_stub_set_io_limits"]
    fn raw_stub_set_io_limits(
        connection: *mut RawConnection,
        read_limit: u64,
        write_limit: u64,
    ) -> u32;
    #[link_name = "foxreq_nss_stub_fail_next"]
    fn raw_stub_fail_next(
        connection: *mut RawConnection,
        operation: u32,
        category: u32,
        nss_code: i32,
        nspr_code: i32,
        message: *const u8,
        message_length: u64,
    ) -> u32;
    #[link_name = "foxreq_nss_stub_written_data"]
    fn raw_stub_written_data(
        connection: *mut RawConnection,
        out_buffer: *mut *mut RawBuffer,
    ) -> u32;
    #[link_name = "foxreq_nss_stub_close_calls"]
    fn raw_stub_close_calls(connection: *mut RawConnection, out_calls: *mut u32) -> u32;
    #[link_name = "foxreq_nss_stub_live_counts"]
    fn raw_stub_live_counts(
        out_runtimes: *mut u32,
        out_connections: *mut u32,
        out_session_caches: *mut u32,
        out_buffers: *mut u32,
    ) -> u32;
}

pub(super) struct ConnectArgs<'a> {
    pub host: &'a [u8],
    pub port: u16,
    pub timeout_millis: u64,
    pub profile_id: &'a [u8],
    pub alpn_wire: &'a [u8],
    pub verification_mode: u32,
    pub session_cache: Option<NonNull<RawSessionCache>>,
}

pub(super) struct IoResult {
    pub code: u32,
    pub transferred: usize,
}

pub(super) struct CertificateResult {
    pub verification_performed: bool,
    pub verified: bool,
    pub category: u32,
    pub nss_code: i32,
    pub nspr_code: i32,
}

pub(super) struct LastError {
    pub category: u32,
    pub nss_code: i32,
    pub nspr_code: i32,
    pub message: Vec<u8>,
}

pub(super) struct LiveCounts {
    pub runtimes: u32,
    pub connections: u32,
    pub session_caches: u32,
    pub buffers: u32,
}

struct BufferGuard(NonNull<RawBuffer>);

impl Drop for BufferGuard {
    fn drop(&mut self) {
        unsafe { raw_buffer_free(self.0.as_ptr()) };
    }
}

pub(super) fn runtime_create() -> Result<NonNull<RawRuntime>, u32> {
    if unsafe { raw_abi_version() } != ABI_VERSION {
        return Err(8);
    }
    let options = RawRuntimeOptions {
        struct_size: struct_size::<RawRuntimeOptions>(),
        abi_version: ABI_VERSION,
        reserved: 0,
    };
    let mut runtime = ptr::null_mut();
    let code = unsafe { raw_runtime_create(&options, &mut runtime) };
    pointer_result(code, runtime)
}

pub(super) fn runtime_free(runtime: NonNull<RawRuntime>) {
    unsafe { raw_runtime_free(runtime.as_ptr()) };
}

pub(super) fn session_cache_create(
    runtime: NonNull<RawRuntime>,
    capacity: u32,
) -> Result<NonNull<RawSessionCache>, u32> {
    let options = RawSessionCacheOptions {
        struct_size: struct_size::<RawSessionCacheOptions>(),
        abi_version: ABI_VERSION,
        capacity,
        reserved: 0,
    };
    let mut cache = ptr::null_mut();
    let code = unsafe { raw_session_cache_create(runtime.as_ptr(), &options, &mut cache) };
    pointer_result(code, cache)
}

pub(super) fn session_cache_free(cache: NonNull<RawSessionCache>) {
    unsafe { raw_session_cache_free(cache.as_ptr()) };
}

pub(super) fn connect(
    runtime: NonNull<RawRuntime>,
    arguments: &ConnectArgs<'_>,
) -> Result<NonNull<RawConnection>, u32> {
    let options = RawConnectOptions {
        struct_size: struct_size::<RawConnectOptions>(),
        abi_version: ABI_VERSION,
        host: raw_slice(arguments.host)?,
        port: arguments.port,
        reserved16: 0,
        verification_mode: arguments.verification_mode,
        timeout_millis: arguments.timeout_millis,
        profile_id: raw_slice(arguments.profile_id)?,
        alpn_wire: raw_slice(arguments.alpn_wire)?,
        session_cache: arguments
            .session_cache
            .map_or(ptr::null_mut(), NonNull::as_ptr),
        reserved: [0; 2],
    };
    let mut connection = ptr::null_mut();
    let code = unsafe { raw_connect(runtime.as_ptr(), &options, &mut connection) };
    pointer_result(code, connection)
}

pub(super) fn connection_free(connection: NonNull<RawConnection>) {
    unsafe { raw_connection_free(connection.as_ptr()) };
}

pub(super) fn negotiated_alpn(connection: NonNull<RawConnection>) -> Result<Vec<u8>, u32> {
    let mut buffer = ptr::null_mut();
    let code = unsafe { raw_negotiated_alpn(connection.as_ptr(), &mut buffer) };
    let buffer = pointer_result(code, buffer)?;
    copy_buffer(buffer)
}

pub(super) fn certificate_result(
    connection: NonNull<RawConnection>,
) -> Result<CertificateResult, u32> {
    let mut result = RawCertificateResult {
        struct_size: struct_size::<RawCertificateResult>(),
        abi_version: ABI_VERSION,
        verification_performed: 0,
        verified: 0,
        category: 0,
        nss_code: 0,
        nspr_code: 0,
        reserved32: 0,
    };
    let code = unsafe { raw_certificate_result(connection.as_ptr(), &mut result) };
    code_result(code)?;
    Ok(CertificateResult {
        verification_performed: result.verification_performed != 0,
        verified: result.verified != 0,
        category: result.category,
        nss_code: result.nss_code,
        nspr_code: result.nspr_code,
    })
}

pub(super) fn read(
    connection: NonNull<RawConnection>,
    destination: &mut [u8],
    timeout_millis: u64,
) -> Result<IoResult, u32> {
    let capacity = length_u64(destination.len())?;
    let pointer = if destination.is_empty() {
        ptr::null_mut()
    } else {
        destination.as_mut_ptr()
    };
    let mut transferred = 0u64;
    let code = unsafe {
        raw_read(
            connection.as_ptr(),
            pointer,
            capacity,
            timeout_millis,
            &mut transferred,
        )
    };
    Ok(IoResult {
        code,
        transferred: checked_transfer(transferred, destination.len())?,
    })
}

pub(super) fn write(
    connection: NonNull<RawConnection>,
    source: &[u8],
    timeout_millis: u64,
) -> Result<IoResult, u32> {
    let length = length_u64(source.len())?;
    let pointer = if source.is_empty() {
        ptr::null()
    } else {
        source.as_ptr()
    };
    let mut transferred = 0u64;
    let code = unsafe {
        raw_write(
            connection.as_ptr(),
            pointer,
            length,
            timeout_millis,
            &mut transferred,
        )
    };
    Ok(IoResult {
        code,
        transferred: checked_transfer(transferred, source.len())?,
    })
}

pub(super) fn close(connection: NonNull<RawConnection>, timeout_millis: u64) -> u32 {
    unsafe { raw_close(connection.as_ptr(), timeout_millis) }
}

pub(super) fn last_error(connection: NonNull<RawConnection>) -> Result<LastError, u32> {
    let mut info = empty_error_info();
    let mut required = 0u64;
    let first = unsafe {
        raw_last_error(
            connection.as_ptr(),
            &mut info,
            ptr::null_mut(),
            0,
            &mut required,
        )
    };
    if first != RESULT_BUFFER_TOO_SMALL && first != RESULT_OK {
        return Err(first);
    }
    let required = usize::try_from(required).map_err(|_| RESULT_INVALID_ARGUMENT)?;
    if required == 0 {
        return Err(RESULT_STATE);
    }
    let mut message = vec![0u8; required];
    let mut second_required = 0u64;
    let second = unsafe {
        raw_last_error(
            connection.as_ptr(),
            &mut info,
            message.as_mut_ptr().cast::<c_char>(),
            length_u64(message.len())?,
            &mut second_required,
        )
    };
    code_result(second)?;
    if usize::try_from(second_required).ok() != Some(message.len()) || message.last() != Some(&0) {
        return Err(RESULT_STATE);
    }
    message.pop();
    Ok(LastError {
        category: info.category,
        nss_code: info.nss_code,
        nspr_code: info.nspr_code,
        message,
    })
}

pub(super) fn stub_set_read_data(connection: NonNull<RawConnection>, data: &[u8]) -> u32 {
    let Ok(length) = length_u64(data.len()) else {
        return RESULT_INVALID_ARGUMENT;
    };
    let pointer = if data.is_empty() {
        ptr::null()
    } else {
        data.as_ptr()
    };
    unsafe { raw_stub_set_read_data(connection.as_ptr(), pointer, length) }
}

pub(super) fn stub_set_io_limits(
    connection: NonNull<RawConnection>,
    read_limit: u64,
    write_limit: u64,
) -> u32 {
    unsafe { raw_stub_set_io_limits(connection.as_ptr(), read_limit, write_limit) }
}

pub(super) fn stub_fail_next_read(
    connection: NonNull<RawConnection>,
    category: u32,
    nss_code: i32,
    nspr_code: i32,
    message: &[u8],
) -> u32 {
    stub_fail_next(
        connection,
        STUB_OPERATION_READ,
        category,
        nss_code,
        nspr_code,
        message,
    )
}

pub(super) fn stub_fail_next_write(
    connection: NonNull<RawConnection>,
    category: u32,
    nss_code: i32,
    nspr_code: i32,
    message: &[u8],
) -> u32 {
    stub_fail_next(
        connection,
        STUB_OPERATION_WRITE,
        category,
        nss_code,
        nspr_code,
        message,
    )
}

pub(super) fn stub_fail_next_close(
    connection: NonNull<RawConnection>,
    category: u32,
    nss_code: i32,
    nspr_code: i32,
    message: &[u8],
) -> u32 {
    stub_fail_next(
        connection,
        STUB_OPERATION_CLOSE,
        category,
        nss_code,
        nspr_code,
        message,
    )
}

fn stub_fail_next(
    connection: NonNull<RawConnection>,
    operation: u32,
    category: u32,
    nss_code: i32,
    nspr_code: i32,
    message: &[u8],
) -> u32 {
    let Ok(length) = length_u64(message.len()) else {
        return RESULT_INVALID_ARGUMENT;
    };
    let pointer = if message.is_empty() {
        ptr::null()
    } else {
        message.as_ptr()
    };
    unsafe {
        raw_stub_fail_next(
            connection.as_ptr(),
            operation,
            category,
            nss_code,
            nspr_code,
            pointer,
            length,
        )
    }
}

pub(super) fn stub_written_data(connection: NonNull<RawConnection>) -> Result<Vec<u8>, u32> {
    let mut buffer = ptr::null_mut();
    let code = unsafe { raw_stub_written_data(connection.as_ptr(), &mut buffer) };
    let buffer = pointer_result(code, buffer)?;
    copy_buffer(buffer)
}

pub(super) fn stub_close_calls(connection: NonNull<RawConnection>) -> Result<u32, u32> {
    let mut calls = 0u32;
    let code = unsafe { raw_stub_close_calls(connection.as_ptr(), &mut calls) };
    code_result(code)?;
    Ok(calls)
}

pub(super) fn stub_live_counts() -> Result<LiveCounts, u32> {
    let mut runtimes = 0u32;
    let mut connections = 0u32;
    let mut session_caches = 0u32;
    let mut buffers = 0u32;
    let code = unsafe {
        raw_stub_live_counts(
            &mut runtimes,
            &mut connections,
            &mut session_caches,
            &mut buffers,
        )
    };
    code_result(code)?;
    Ok(LiveCounts {
        runtimes,
        connections,
        session_caches,
        buffers,
    })
}

fn copy_buffer(buffer: NonNull<RawBuffer>) -> Result<Vec<u8>, u32> {
    let buffer = BufferGuard(buffer);
    let mut data = ptr::null();
    let mut length = 0u64;
    let code = unsafe { raw_buffer_view(buffer.0.as_ptr(), &mut data, &mut length) };
    code_result(code)?;
    let length = usize::try_from(length).map_err(|_| RESULT_INVALID_ARGUMENT)?;
    if length == 0 {
        return Ok(Vec::new());
    }
    if data.is_null() {
        return Err(RESULT_STATE);
    }
    Ok(unsafe { slice::from_raw_parts(data, length) }.to_vec())
}

fn empty_error_info() -> RawErrorInfo {
    RawErrorInfo {
        struct_size: struct_size::<RawErrorInfo>(),
        abi_version: ABI_VERSION,
        category: 0,
        reserved32: 0,
        nss_code: 0,
        nspr_code: 0,
        auxiliary: 0,
    }
}

fn raw_slice(value: &[u8]) -> Result<RawSlice, u32> {
    Ok(RawSlice {
        data: if value.is_empty() {
            ptr::null()
        } else {
            value.as_ptr()
        },
        length: length_u64(value.len())?,
    })
}

fn pointer_result<T>(code: u32, pointer: *mut T) -> Result<NonNull<T>, u32> {
    code_result(code)?;
    NonNull::new(pointer).ok_or(RESULT_STATE)
}

fn code_result(code: u32) -> Result<(), u32> {
    if code == RESULT_OK {
        Ok(())
    } else {
        Err(code)
    }
}

fn checked_transfer(value: u64, maximum: usize) -> Result<usize, u32> {
    let value = usize::try_from(value).map_err(|_| RESULT_STATE)?;
    if value > maximum {
        Err(RESULT_STATE)
    } else {
        Ok(value)
    }
}

fn length_u64(value: usize) -> Result<u64, u32> {
    u64::try_from(value).map_err(|_| RESULT_INVALID_ARGUMENT)
}

fn struct_size<T>() -> u32 {
    u32::try_from(size_of::<T>()).unwrap_or(u32::MAX)
}
