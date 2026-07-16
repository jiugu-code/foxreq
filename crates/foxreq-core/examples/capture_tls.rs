use std::{env, error::Error, io, net::IpAddr, path::PathBuf, time::Duration};

use foxreq_core::tls::{ConnectConfig, RequestVerification, Runtime, RuntimeConfig, SessionCache};

const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Eq, PartialEq)]
enum Mode {
    Cold,
    Resumed,
}

struct Options {
    runtime: PathBuf,
    ca_der: PathBuf,
    host: String,
    port: u16,
    mode: Mode,
    count: usize,
}

fn main() -> Result<(), Box<dyn Error>> {
    let options = parse_options(env::args().skip(1))?;
    let ca_der = std::fs::read(&options.ca_der)?;
    let runtime = Runtime::new_with_config(RuntimeConfig {
        runtime_dir: &options.runtime,
        trust_anchors_der: &[&ca_der],
        profile_id: "firefox_152",
    })?;
    let resumed_cache = if options.mode == Mode::Resumed {
        Some(runtime.session_cache(u32::try_from(options.count)?)?)
    } else {
        None
    };
    for _ in 0..options.count {
        if options.mode == Mode::Cold {
            let cold_cache = runtime.session_cache(1)?;
            exchange(&runtime, Some(&cold_cache), &options)?;
        } else {
            exchange(&runtime, resumed_cache.as_ref(), &options)?;
        }
    }
    println!("completed={}", options.count);
    Ok(())
}

fn exchange(
    runtime: &Runtime,
    cache: Option<&SessionCache>,
    options: &Options,
) -> Result<(), Box<dyn Error>> {
    let deadline = Duration::from_secs(10);
    let mut connection = runtime.connect(
        &ConnectConfig {
            host: &options.host,
            port: options.port,
            timeout: deadline,
            profile_id: "firefox_152",
            // NSS places its preferred protocol last in the input vector.
            alpn_wire: b"\x08http/1.1\x02h2",
            verification: RequestVerification::Default,
        },
        cache,
    )?;
    let request = format!(
        "GET / HTTP/1.1\r\nHost: {}:{}\r\nConnection: close\r\n\r\n",
        options.host, options.port
    );
    let request = request.as_bytes();
    let mut written = 0;
    while written < request.len() {
        let amount = connection.write(&request[written..], deadline)?;
        if amount == 0 {
            return Err(
                io::Error::new(io::ErrorKind::WriteZero, "TLS write made no progress").into(),
            );
        }
        written += amount;
    }
    let mut total = 0usize;
    let mut buffer = [0u8; 4096];
    loop {
        let amount = connection.read(&mut buffer, deadline)?;
        if amount == 0 {
            break;
        }
        total = total.checked_add(amount).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "response length overflow")
        })?;
        if total > MAX_RESPONSE_BYTES {
            return Err(
                io::Error::new(io::ErrorKind::InvalidData, "response exceeds limit").into(),
            );
        }
    }
    connection.close(Duration::from_secs(1))?;
    Ok(())
}

fn parse_options(arguments: impl Iterator<Item = String>) -> Result<Options, Box<dyn Error>> {
    let mut runtime = None;
    let mut ca_der = None;
    let mut host = None;
    let mut port = None;
    let mut mode = None;
    let mut count = None;
    let mut arguments = arguments;
    while let Some(argument) = arguments.next() {
        let value = arguments
            .next()
            .ok_or_else(|| invalid("missing option value"))?;
        match argument.as_str() {
            "--runtime" => runtime = Some(PathBuf::from(value)),
            "--ca-der" => ca_der = Some(PathBuf::from(value)),
            "--host" => host = Some(value),
            "--port" => port = Some(value.parse::<u16>()?),
            "--mode" => {
                mode = Some(match value.as_str() {
                    "cold" => Mode::Cold,
                    "resumed" => Mode::Resumed,
                    _ => return Err(invalid("mode must be cold or resumed").into()),
                });
            }
            "--count" => count = Some(value.parse::<usize>()?),
            _ => return Err(invalid("unknown option").into()),
        }
    }
    let host = host.ok_or_else(|| invalid("--host is required"))?;
    let address = host.parse::<IpAddr>()?;
    if !address.is_loopback() {
        return Err(invalid("host must be a loopback IP literal").into());
    }
    let port = port.ok_or_else(|| invalid("--port is required"))?;
    if port == 0 {
        return Err(invalid("port must be positive").into());
    }
    let count = count.ok_or_else(|| invalid("--count is required"))?;
    if !(1..=1000).contains(&count) {
        return Err(invalid("count must be between 1 and 1000").into());
    }
    Ok(Options {
        runtime: runtime.ok_or_else(|| invalid("--runtime is required"))?,
        ca_der: ca_der.ok_or_else(|| invalid("--ca-der is required"))?,
        host,
        port,
        mode: mode.ok_or_else(|| invalid("--mode is required"))?,
        count,
    })
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
