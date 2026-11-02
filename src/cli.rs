// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use crate::config::parse_object;
use crate::error::fail;
use crate::relying_party::RelyingParty;
use crate::x509util::{self, create_self_signed_key_pair};
use serde_json::Value;
use std::collections::HashMap;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

const USAGE: &str = "Usage:\n  wsfed-caep generate-keys --config <wsfed.json> [--cn <name>] [--days <n>] [--bits <n>] [--force]\n  wsfed-caep generate-keys --key <file> --cert <file> [--cn <name>] [--days <n>] [--bits <n>] [--force]\n      A new RSA key and a self-signed certificate, written where the configuration's privateKey and\n      certificate point (or to --key and --cert). Refuses to replace existing files without --force.\n      The key decrypts encrypted assertions and can authenticate the Shared Signals receiver (mutual\n      TLS); WS-Federation itself signs nothing. The common name defaults to one naming the realm.\n\n  wsfed-caep metadata --config <wsfed.json> [--out <file>]\n      This relying party's federation metadata, from the configuration (and its certificate, when it\n      has one): give it to the identity provider. Written to --out, or to standard output.";

fn parse_cli(argv: &[String]) -> std::result::Result<(String, HashMap<String, String>), String> {
    if argv.is_empty() { return Ok((String::new(), HashMap::new())); }
    let command = argv[0].clone();
    let rest = &argv[1..];
    let mut args = HashMap::new();
    let mut index = 0;
    while index < rest.len() {
        let item = &rest[index];
        if !item.starts_with("--") { return Err(format!("unexpected argument {item}\n\n{USAGE}")); }
        let key = &item[2..];
        if key == "force" || key == "help" {
            args.insert(key.to_string(), "true".to_string());
            index += 1;
            continue;
        }
        if index + 1 >= rest.len() || rest[index + 1].starts_with("--") {
            return Err(format!("--{key} needs a value\n\n{USAGE}"));
        }
        args.insert(key.to_string(), rest[index + 1].clone());
        index += 2;
    }
    Ok((command, args))
}

fn clip_runes(value: &str, n: usize) -> String {
    value.chars().take(n).collect()
}

fn strip_file(value: &str) -> &str {
    value.strip_prefix("file:").unwrap_or(value)
}

fn key_paths(args: &HashMap<String, String>) -> std::result::Result<(String, String, String), String> {
    let config_path = args.get("config").cloned().unwrap_or_default();
    let mut key = args.get("key").cloned().unwrap_or_default();
    let mut cert = args.get("cert").cloned().unwrap_or_default();
    let mut common_name = args.get("cn").cloned().unwrap_or_default();
    if !config_path.is_empty() {
        let raw = std::fs::read_to_string(&config_path).map_err(|err| err.to_string())?;
        let parsed = parse_object(&raw).map_err(|err| err.to_string())?;
        let base = std::fs::canonicalize(&config_path).unwrap_or_else(|_| PathBuf::from(&config_path));
        let base = base.parent().unwrap_or(Path::new("."));
        let at = |value: &str, what: &str| -> std::result::Result<String, String> {
            if value.is_empty() || value.contains("-----BEGIN ") {
                return Err(format!("{config_path}'s {what} must be a file path for generate-keys to write to"));
            }
            let value = strip_file(value);
            if Path::new(value).is_absolute() { Ok(value.to_string()) } else { Ok(base.join(value).to_string_lossy().into_owned()) }
        };
        if key.is_empty() {
            if let Some(text) = parsed.get("privateKey").and_then(|item| item.as_str()) {
                if !text.is_empty() { key = at(text, "privateKey")?; }
            }
        }
        if cert.is_empty() {
            if let Some(text) = parsed.get("certificate").and_then(|item| item.as_str()) {
                if !text.is_empty() { cert = at(text, "certificate")?; }
            }
        }
        if common_name.is_empty() {
            if let Some(realm) = parsed.get("realm").and_then(|item| item.as_str()) {
                if !realm.is_empty() { common_name = clip_runes(&format!("wsfed-caep-nodejs relying party {realm}"), 64); }
            }
        }
    }
    if key.is_empty() || cert.is_empty() {
        return Err(format!("generate-keys needs --config, or --key and --cert\n\n{USAGE}"));
    }
    let key = std::fs::canonicalize(Path::new(&key).parent().unwrap_or(Path::new("."))).unwrap_or_else(|_| PathBuf::from(".")).join(Path::new(&key).file_name().unwrap_or_default());
    let cert_abs = std::fs::canonicalize(Path::new(&cert).parent().unwrap_or(Path::new("."))).unwrap_or_else(|_| PathBuf::from(".")).join(Path::new(&cert).file_name().unwrap_or_default());
    if common_name.is_empty() { common_name = "wsfed-caep-nodejs relying party".to_string(); }
    Ok((key.to_string_lossy().into_owned(), cert_abs.to_string_lossy().into_owned(), common_name))
}

fn exists(path: &str) -> bool { Path::new(path).exists() }

pub fn main(argv: &[String], mut out: impl Write) -> i32 {
    let (command, args) = match parse_cli(argv) {
        Ok(value) => value,
        Err(err) => { eprintln!("{err}"); return 1; }
    };
    if command.is_empty() || args.get("help").map(String::as_str) == Some("true") || command == "help" {
        let _ = writeln!(out, "{USAGE}");
        return 0;
    }
    if command == "generate-keys" {
        let (key, cert, common_name) = match key_paths(&args) {
            Ok(value) => value,
            Err(err) => { eprintln!("{err}"); return 1; }
        };
        if args.get("force").map(String::as_str) != Some("true") && (exists(&key) || exists(&cert)) {
            let which = if exists(&key) { &key } else { &cert };
            eprintln!("{which} already exists; pass --force to replace the key pair.\nReplacing it means giving the identity provider the new metadata before it next encrypts to this relying party.");
            return 1;
        }
        let mut days = 1095i64;
        let mut bits = 3072usize;
        if let Some(text) = args.get("days") {
            match text.parse::<i64>() { Ok(value) if value > 0 => days = value, _ => { eprintln!("--days must be a positive whole number"); return 1; } }
        }
        if let Some(text) = args.get("bits") {
            match text.parse::<usize>() { Ok(2048) | Ok(3072) | Ok(4096) => bits = text.parse().unwrap_or(3072), _ => { eprintln!("--bits must be 2048, 3072 or 4096"); return 1; } }
        }
        let pair = match create_self_signed_key_pair(&common_name, days, bits) {
            Ok(value) => value,
            Err(err) => { eprintln!("{err}"); return 1; }
        };
        if let Some(dir) = Path::new(&key).parent() { let _ = std::fs::create_dir_all(dir); }
        if let Some(dir) = Path::new(&cert).parent() { let _ = std::fs::create_dir_all(dir); }
        if write_mode(&key, pair.private_key_pem.as_bytes(), 0o600).is_err() || write_mode(&cert, pair.certificate_pem.as_bytes(), 0o644).is_err() {
            eprintln!("the key pair could not be written");
            return 1;
        }
        let _ = writeln!(out, "Wrote the private key  {key} (mode 600)");
        let _ = writeln!(out, "Wrote the certificate  {cert}");
        let _ = writeln!(out, "  subject   {}", x509util::subject_string(&pair.certificate_der));
        return 0;
    }
    if command == "metadata" {
        let config_path = args.get("config").cloned().unwrap_or_default();
        if config_path.is_empty() { eprintln!("metadata needs --config\n\n{USAGE}"); return 1; }
        let raw = match std::fs::read_to_string(&config_path) { Ok(value) => value, Err(err) => { eprintln!("{err}"); return 1; } };
        let mut parsed = match parse_object(&raw) { Ok(value) => value, Err(err) => { eprintln!("{err}"); return 1; } };
        parsed.remove("idpCa");
        let base = std::fs::canonicalize(&config_path).unwrap_or_else(|_| PathBuf::from(&config_path));
        let base = base.parent().unwrap_or(Path::new(".")).to_path_buf();
        let party = match RelyingParty::create(&parsed, &base) { Ok(value) => value, Err(err) => { eprintln!("{err}"); return 1; } };
        let xml = party.metadata_xml();
        if let Some(target) = args.get("out") {
            if let Some(dir) = Path::new(target).parent() { let _ = std::fs::create_dir_all(dir); }
            if std::fs::write(target, xml.as_bytes()).is_err() { eprintln!("the metadata could not be written"); return 1; }
            let _ = writeln!(out, "Wrote the relying party metadata to {target}");
        } else {
            let _ = write!(out, "{xml}");
        }
        return 0;
    }
    eprintln!("unknown command {command}\n\n{USAGE}");
    let _ = fail("config", "");
    let _ = Value::Null;
    1
}

fn write_mode(path: &str, bytes: &[u8], mode: u32) -> io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(mode).open(path)?;
    file.write_all(bytes)
}

pub fn main_args() -> i32 {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    main(&argv, io::stdout())
}
