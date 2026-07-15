#![allow(unsafe_code)]

use std::{
    io::Read,
    panic::{catch_unwind, AssertUnwindSafe},
    ptr::NonNull,
    slice,
};

use ruzstd::decoding::StreamingDecoder;

use super::ffi;

pub(super) fn decode_zlib(input: &[u8], output: &mut [u8]) -> Result<usize, ()> {
    read_bounded(flate2::read::ZlibDecoder::new(input), output)
}

pub(super) fn decode_brotli(input: &[u8], output: &mut [u8]) -> Result<usize, ()> {
    read_bounded(
        brotli_decompressor::Decompressor::new(input, 4 * 1024),
        output,
    )
}

pub(super) fn decode_zstd(input: &[u8], output: &mut [u8]) -> Result<usize, ()> {
    let decoder = StreamingDecoder::new(input).map_err(|_| ())?;
    read_bounded(decoder, output)
}

pub(super) fn register(runtime: NonNull<ffi::RawRuntime>) -> Result<(), u32> {
    ffi::register_certificate_decoders(
        runtime,
        decode_zlib_callback,
        decode_brotli_callback,
        decode_zstd_callback,
    )
}

unsafe extern "C" fn decode_zlib_callback(
    input: *const u8,
    input_length: usize,
    output: *mut u8,
    output_length: usize,
    used_length: *mut usize,
) -> i32 {
    decode_callback(
        input,
        input_length,
        output,
        output_length,
        used_length,
        decode_zlib,
    )
}

unsafe extern "C" fn decode_brotli_callback(
    input: *const u8,
    input_length: usize,
    output: *mut u8,
    output_length: usize,
    used_length: *mut usize,
) -> i32 {
    decode_callback(
        input,
        input_length,
        output,
        output_length,
        used_length,
        decode_brotli,
    )
}

unsafe extern "C" fn decode_zstd_callback(
    input: *const u8,
    input_length: usize,
    output: *mut u8,
    output_length: usize,
    used_length: *mut usize,
) -> i32 {
    decode_callback(
        input,
        input_length,
        output,
        output_length,
        used_length,
        decode_zstd,
    )
}

fn decode_callback(
    input: *const u8,
    input_length: usize,
    output: *mut u8,
    output_length: usize,
    used_length: *mut usize,
    decoder: fn(&[u8], &mut [u8]) -> Result<usize, ()>,
) -> i32 {
    if used_length.is_null() {
        return -1;
    }
    unsafe { *used_length = 0 };
    if (input_length > 0 && input.is_null()) || (output_length > 0 && output.is_null()) {
        return -1;
    }

    let input = if input_length == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(input, input_length) }
    };
    let output = if output_length == 0 {
        &mut []
    } else {
        unsafe { slice::from_raw_parts_mut(output, output_length) }
    };

    match catch_unwind(AssertUnwindSafe(|| decoder(input, output))) {
        Ok(Ok(used)) if used <= output_length => {
            unsafe { *used_length = used };
            0
        }
        Ok(Ok(_)) | Ok(Err(())) | Err(_) => -1,
    }
}

fn read_bounded(mut decoder: impl Read, output: &mut [u8]) -> Result<usize, ()> {
    let mut used = 0;
    while used < output.len() {
        let amount = decoder.read(&mut output[used..]).map_err(|_| ())?;
        if amount == 0 {
            return Ok(used);
        }
        used = used.checked_add(amount).ok_or(())?;
    }
    let mut extra = [0_u8; 1];
    match decoder.read(&mut extra) {
        Ok(0) => Ok(used),
        Ok(_) | Err(_) => Err(()),
    }
}

#[cfg(test)]
mod tests {
    use std::ptr;

    use super::{
        decode_brotli, decode_brotli_callback, decode_zlib, decode_zlib_callback, decode_zstd,
        decode_zstd_callback,
    };

    const TEXT: &[u8] = b"foxreq certificate compression test vector";
    const ZLIB: &[u8] = &[
        120, 156, 5, 193, 193, 13, 0, 32, 8, 3, 192, 85, 88, 205, 52, 37, 225, 161, 40, 52, 198,
        241, 189, 243, 124, 197, 99, 96, 41, 60, 48, 68, 67, 206, 93, 236, 142, 92, 38, 182, 236,
        18, 202, 250, 101, 86, 16, 158,
    ];
    const BROTLI: &[u8] = &[
        27, 41, 0, 224, 197, 115, 120, 124, 135, 120, 69, 90, 107, 65, 100, 1, 6, 30, 181, 138,
        173, 252, 101, 230, 83, 94, 162, 164, 35, 230, 2,
    ];
    const ZSTD: &[u8] = &[
        40, 181, 47, 253, 4, 88, 209, 0, 0, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107,
        108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 92, 131, 137,
        250,
    ];

    #[test]
    fn decodes_the_three_firefox_algorithms_into_bounded_buffers() {
        type Decoder = fn(&[u8], &mut [u8]) -> Result<usize, ()>;
        for (compressed, expected, decoder) in [
            (ZLIB, TEXT, decode_zlib as Decoder),
            (BROTLI, TEXT, decode_brotli as Decoder),
            (ZSTD, b"abcdefghijklmnopqrstuvwxyz", decode_zstd as Decoder),
        ] {
            let mut output = vec![0; expected.len()];
            let used = decoder(compressed, &mut output).unwrap();
            assert_eq!(expected, &output[..used]);
        }
    }

    #[test]
    fn rejects_malformed_input_and_output_overflow() {
        let mut output = [0; 4];
        assert!(decode_zlib(ZLIB, &mut output).is_err());
        assert!(decode_brotli(&BROTLI[..4], &mut output).is_err());
        assert!(decode_zstd(&ZSTD[..4], &mut output).is_err());
    }

    #[test]
    fn ffi_callbacks_report_exact_output_lengths() {
        type Callback = unsafe extern "C" fn(*const u8, usize, *mut u8, usize, *mut usize) -> i32;
        for (compressed, expected, callback) in [
            (ZLIB, TEXT, decode_zlib_callback as Callback),
            (BROTLI, TEXT, decode_brotli_callback as Callback),
            (
                ZSTD,
                b"abcdefghijklmnopqrstuvwxyz".as_slice(),
                decode_zstd_callback as Callback,
            ),
        ] {
            let mut output = vec![0; expected.len()];
            let mut used = usize::MAX;
            let result = unsafe {
                callback(
                    compressed.as_ptr(),
                    compressed.len(),
                    output.as_mut_ptr(),
                    output.len(),
                    &mut used,
                )
            };
            assert_eq!(result, 0);
            assert_eq!(used, expected.len());
            assert_eq!(&output[..used], expected);
        }
    }

    #[test]
    fn ffi_callbacks_reject_invalid_pointers_and_decode_failures() {
        let mut output = [0; 4];
        let mut used = usize::MAX;
        assert_eq!(
            unsafe {
                decode_zlib_callback(ptr::null(), 1, output.as_mut_ptr(), output.len(), &mut used)
            },
            -1
        );
        assert_eq!(used, 0);

        used = usize::MAX;
        assert_eq!(
            unsafe {
                decode_zlib_callback(ZLIB.as_ptr(), ZLIB.len(), ptr::null_mut(), 1, &mut used)
            },
            -1
        );
        assert_eq!(used, 0);

        assert_eq!(
            unsafe {
                decode_zlib_callback(
                    ZLIB.as_ptr(),
                    ZLIB.len(),
                    output.as_mut_ptr(),
                    output.len(),
                    ptr::null_mut(),
                )
            },
            -1
        );

        used = usize::MAX;
        assert_eq!(
            unsafe {
                decode_brotli_callback(
                    BROTLI[..4].as_ptr(),
                    4,
                    output.as_mut_ptr(),
                    output.len(),
                    &mut used,
                )
            },
            -1
        );
        assert_eq!(used, 0);
    }
}
