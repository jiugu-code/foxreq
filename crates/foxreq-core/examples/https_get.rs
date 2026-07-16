use std::{env, error::Error, path::PathBuf, time::Duration};

use foxreq_core::{
    http1::{ClientRequest, Http1Client, Version},
    tls::{Runtime, RuntimeConfig},
    transport::NssConnector,
};

struct Options {
    runtime: PathBuf,
    ca_der: PathBuf,
    url: String,
}

fn main() -> Result<(), Box<dyn Error>> {
    let options = parse_options(env::args().skip(1))?;
    let ca_der = std::fs::read(&options.ca_der)?;
    let runtime = Runtime::new_with_config(RuntimeConfig {
        runtime_dir: &options.runtime,
        trust_anchors_der: &[&ca_der],
        profile_id: "firefox_152",
    })?;
    let connector = NssConnector::new(runtime, 16)?;
    let mut client = Http1Client::new(connector);
    let response = client.execute(ClientRequest::get(options.url, Duration::from_secs(30)))?;
    let version = match response.version {
        Version::Http10 => "HTTP/1.0",
        Version::Http11 => "HTTP/1.1",
    };

    println!("status={}", response.status);
    println!("http_version={version}");
    println!("body_length={}", response.body.len());
    Ok(())
}

fn parse_options(arguments: impl IntoIterator<Item = String>) -> Result<Options, &'static str> {
    let mut runtime = None;
    let mut ca_der = None;
    let mut url = None;
    let mut arguments = arguments.into_iter();
    while let Some(argument) = arguments.next() {
        let destination = match argument.as_str() {
            "--runtime" => &mut runtime,
            "--ca-der" => &mut ca_der,
            "--url" => &mut url,
            _ => return Err("usage: https_get --runtime DIR --ca-der FILE --url HTTPS_URL"),
        };
        if destination.is_some() {
            return Err("duplicate https_get option");
        }
        *destination = Some(arguments.next().ok_or("missing https_get option value")?);
    }
    Ok(Options {
        runtime: runtime.map(PathBuf::from).ok_or("--runtime is required")?,
        ca_der: ca_der.map(PathBuf::from).ok_or("--ca-der is required")?,
        url: url.ok_or("--url is required")?,
    })
}

#[cfg(test)]
mod tests {
    use super::parse_options;

    #[test]
    fn requires_every_explicit_input() {
        assert!(parse_options([]).is_err());
        assert!(parse_options(["--runtime".to_owned(), "runtime".to_owned()]).is_err());
    }

    #[test]
    fn accepts_runtime_ca_and_url_once() {
        let options = parse_options([
            "--runtime".to_owned(),
            "runtime".to_owned(),
            "--ca-der".to_owned(),
            "ca.der".to_owned(),
            "--url".to_owned(),
            "https://127.0.0.1/".to_owned(),
        ])
        .unwrap();
        assert_eq!(options.url, "https://127.0.0.1/");
    }
}
