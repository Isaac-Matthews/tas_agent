// TEE Attestation Service Agent
//
// Copyright 2026 Hewlett Packard Enterprise Development LP.
// SPDX-License-Identifier: MIT
//
// Plain PKCS#10 CSR construction for the TAS certificate flow.

use crate::certify::keygen::AgentKey;
use rsa::pkcs1v15::Signature;
use rsa::signature::{Keypair, Signer};
use std::error::Error;
use std::net::IpAddr;
use std::str::FromStr;
use uuid::Uuid;
use x509_cert::builder::{Builder, RequestBuilder};
use x509_cert::der::asn1::{Ia5String, OctetString};
use x509_cert::der::pem::LineEnding;
use x509_cert::der::{Encode, EncodePem};
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::SubjectAltName;
use x509_cert::name::Name;
use x509_cert::request::{CertReq, CertReqInfo};
use x509_cert::spki::{
    DynSignatureAlgorithmIdentifier, SignatureBitStringEncoding, SubjectPublicKeyInfoOwned,
};

const MAX_FQDN_COMPONENT_LEN: usize = 47;
const MAX_HOSTNAME_COMPONENT_LEN: usize = 32;
const UUID_SUFFIX_HEX_LEN: usize = 12;

/// Maximum length of a Common Name value (X.509 `ub-common-name`, RFC 5280).
const MAX_COMMON_NAME_LEN: usize = 64;

/// Maximum number of Subject Alternative Names accepted for a single CSR.
const MAX_SANS: usize = 64;

/// A single Subject Alternative Name requested for the CSR.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SanEntry {
    /// `dNSName` general name.
    Dns(String),
    /// `iPAddress` general name.
    Ip(IpAddr),
    /// `uniformResourceIdentifier` general name.
    Uri(String),
    /// `rfc822Name` (email address) general name.
    Email(String),
}

/// Parses a `TYPE:VALUE` Subject Alternative Name token.
///
/// Accepts the OpenSSL-style type tokens `DNS`, `IP`, `URI`, and `email`
/// (case-insensitive). The token is split on the first `:` so that IPv6
/// addresses and URIs containing colons are preserved.
///
/// # Errors
///
/// Returns an error string if the token has no `:`, an empty value, an
/// unsupported type, a value containing whitespace, a non-ASCII value for the
/// IA5String-encoded types, or an unparseable IP address.
pub fn parse_san(s: &str) -> Result<SanEntry, String> {
    let (kind, value) = s
        .split_once(':')
        .ok_or_else(|| format!("invalid SAN {s:?}, expected TYPE:VALUE"))?;
    let value = value.trim();
    if value.is_empty() {
        return Err(format!("invalid SAN {s:?}: empty value"));
    }
    if value.chars().any(char::is_whitespace) {
        return Err(format!(
            "invalid SAN {s:?}: value must not contain whitespace"
        ));
    }
    match kind.trim().to_ascii_lowercase().as_str() {
        "dns" => {
            ensure_ascii(value, "DNS")?;
            Ok(SanEntry::Dns(value.to_string()))
        }
        "uri" => {
            ensure_ascii(value, "URI")?;
            Ok(SanEntry::Uri(value.to_string()))
        }
        "email" => {
            ensure_ascii(value, "email")?;
            Ok(SanEntry::Email(value.to_string()))
        }
        "ip" => value
            .parse::<IpAddr>()
            .map(SanEntry::Ip)
            .map_err(|e| format!("invalid IP in SAN {s:?}: {e}")),
        other => Err(format!(
            "unsupported SAN type {other:?} (expected dns|ip|uri|email)"
        )),
    }
}

fn ensure_ascii(value: &str, label: &str) -> Result<(), String> {
    if value.is_ascii() {
        Ok(())
    } else {
        Err(format!("{label} SAN must be ASCII (IA5String): {value:?}"))
    }
}

/// Validates a user-supplied Common Name for safe use in the CSR subject.
///
/// The value is trimmed and must be non-empty, at most [`MAX_COMMON_NAME_LEN`]
/// characters, and free of RFC 4514 distinguished-name metacharacters and
/// control characters so that it cannot inject additional relative
/// distinguished names into the subject.
///
/// # Errors
///
/// Returns an error string describing the first validation failure.
pub fn parse_common_name(s: &str) -> Result<String, String> {
    let cn = s.trim();
    if cn.is_empty() {
        return Err("common name must not be empty".to_string());
    }
    if cn.chars().count() > MAX_COMMON_NAME_LEN {
        return Err(format!(
            "common name exceeds {MAX_COMMON_NAME_LEN} characters"
        ));
    }
    const FORBIDDEN: &[char] = &[',', '+', '=', '"', '\\', '<', '>', ';', '#'];
    if let Some(bad) = cn.chars().find(|c| c.is_control() || FORBIDDEN.contains(c)) {
        return Err(format!("common name contains forbidden character {bad:?}"));
    }
    Ok(cn.to_string())
}

pub fn generate_tee_common_name() -> String {
    let uuid = Uuid::new_v4();
    let hostname = hostname::get()
        .ok()
        .and_then(|name| name.into_string().ok())
        .map(|name| name.trim().to_string())
        .filter(|name| !name.is_empty());
    generate_tee_common_name_from_system_hostname(hostname.as_deref(), uuid)
}

fn generate_tee_common_name_from_system_hostname(hostname: Option<&str>, uuid: Uuid) -> String {
    match hostname {
        Some(hostname) if hostname.contains('.') => {
            generate_tee_common_name_from_fqdn(Some(hostname), uuid)
        }
        _ => generate_tee_common_name_from_hostname(hostname, uuid),
    }
}

fn generate_tee_common_name_from_fqdn(hostname: Option<&str>, uuid: Uuid) -> String {
    let hostname = hostname
        .map(sanitize_fqdn_component)
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "unknown".to_string());
    let uuid_simple = uuid.simple().to_string();
    let suffix = &uuid_simple[..UUID_SUFFIX_HEX_LEN];
    format!("tee.{}-{}", hostname, suffix)
}

fn generate_tee_common_name_from_hostname(hostname: Option<&str>, uuid: Uuid) -> String {
    let hostname = hostname
        .map(sanitize_hostname_component)
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "unknown".to_string());
    let uuid_simple = uuid.simple().to_string();
    let suffix = &uuid_simple[..UUID_SUFFIX_HEX_LEN];
    format!("tas.{}-{}", hostname, suffix)
}

fn sanitize_hostname_component(hostname: &str) -> String {
    let mut sanitized = String::with_capacity(hostname.len().min(MAX_HOSTNAME_COMPONENT_LEN));
    let mut last_was_hyphen = false;

    for ch in hostname.chars().flat_map(char::to_lowercase) {
        let mapped = if ch.is_ascii_alphanumeric() { ch } else { '-' };

        if mapped == '-' {
            if sanitized.is_empty() || last_was_hyphen {
                continue;
            }
            last_was_hyphen = true;
        } else {
            last_was_hyphen = false;
        }

        sanitized.push(mapped);

        if sanitized.len() >= MAX_HOSTNAME_COMPONENT_LEN {
            break;
        }
    }

    while sanitized.ends_with('-') {
        sanitized.pop();
    }

    sanitized
}

fn sanitize_fqdn_component(hostname: &str) -> String {
    let mut sanitized = String::with_capacity(hostname.len().min(MAX_FQDN_COMPONENT_LEN));
    let mut last_was_separator = false;

    for ch in hostname.chars().flat_map(char::to_lowercase) {
        let mapped = if ch.is_ascii_alphanumeric() || ch == '.' || ch == '-' {
            ch
        } else {
            '-'
        };

        if mapped == '-' || mapped == '.' {
            if sanitized.is_empty() || last_was_separator {
                continue;
            }
            last_was_separator = true;
        } else {
            last_was_separator = false;
        }

        sanitized.push(mapped);

        if sanitized.len() >= MAX_FQDN_COMPONENT_LEN {
            break;
        }
    }

    while sanitized.ends_with('-') || sanitized.ends_with('.') {
        sanitized.pop();
    }

    sanitized
}

fn to_general_names(sans: &[SanEntry]) -> Result<Vec<GeneralName>, Box<dyn Error>> {
    sans.iter()
        .map(|san| {
            Ok(match san {
                SanEntry::Dns(v) => GeneralName::DnsName(Ia5String::new(v)?),
                SanEntry::Uri(v) => GeneralName::UniformResourceIdentifier(Ia5String::new(v)?),
                SanEntry::Email(v) => GeneralName::Rfc822Name(Ia5String::new(v)?),
                SanEntry::Ip(ip) => {
                    let octets: Vec<u8> = match ip {
                        IpAddr::V4(a) => a.octets().to_vec(),
                        IpAddr::V6(a) => a.octets().to_vec(),
                    };
                    GeneralName::IpAddress(OctetString::new(octets)?)
                }
            })
        })
        .collect()
}

/// Builds a signed PKCS#10 certificate signing request in PEM form.
///
/// When `sans` is empty the request is constructed directly with empty
/// attributes, preserving the historical byte-for-byte output (no
/// `extensionRequest` attribute). When one or more SANs are supplied a
/// `SubjectAltName` extension is added via the request builder.
///
/// # Errors
///
/// Returns an error if more than [`MAX_SANS`] SANs are requested, if a SAN
/// value cannot be encoded, or if CSR construction, signing, or PEM encoding
/// fails.
pub fn build_plain_csr(
    key: &AgentKey,
    common_name: &str,
    sans: &[SanEntry],
) -> Result<String, Box<dyn Error>> {
    if sans.len() > MAX_SANS {
        return Err(format!("too many SANs: {} (max {MAX_SANS})", sans.len()).into());
    }

    let subject = Name::from_str(&format!("CN={common_name}"))?;
    let signing_key = key.rsa_4096_signing_key();

    if sans.is_empty() {
        let verifying_key = signing_key.verifying_key();
        let public_key = SubjectPublicKeyInfoOwned::from_key(verifying_key)?;
        let info = CertReqInfo {
            version: Default::default(),
            subject,
            public_key,
            attributes: Default::default(),
        };
        let info_der = info.to_der()?;
        let signature: Signature = signing_key.sign(&info_der);
        let csr = CertReq {
            info,
            algorithm: signing_key.signature_algorithm_identifier()?,
            signature: signature.to_bitstring()?,
        };
        return Ok(csr.to_pem(LineEnding::LF)?);
    }

    let general_names = to_general_names(sans)?;
    let mut builder = RequestBuilder::new(subject, &signing_key)?;
    builder.add_extension(&SubjectAltName(general_names))?;
    let csr = builder.build::<Signature>()?;
    Ok(csr.to_pem(LineEnding::LF)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs1v15::VerifyingKey;
    use rsa::signature::Verifier;
    use x509_cert::der::{DecodePem, Encode};
    use x509_cert::request::CertReq;
    use x509_cert::spki::SubjectPublicKeyInfoRef;

    fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn sanitizes_hostname_component() {
        assert_eq!(sanitize_hostname_component("CVM_Prod.01"), "cvm-prod-01");
        assert_eq!(sanitize_hostname_component("---bad///name---"), "bad-name");
        assert_eq!(sanitize_hostname_component(""), "");
    }

    #[test]
    fn sanitizes_fqdn_component() {
        assert_eq!(
            sanitize_fqdn_component("Node1.Dev_Prod.Example.Com"),
            "node1.dev-prod.example.com"
        );
        assert_eq!(sanitize_fqdn_component("...bad///name..."), "bad-name");
    }

    #[test]
    fn generated_common_name_uses_fqdn_when_available() {
        let uuid = Uuid::parse_str("3f2a9c14-8b7d-4e21-a9f0-1c2d3e4f5a6b").unwrap();
        let cn = generate_tee_common_name_from_fqdn(Some("node1.dev.example.com"), uuid);
        assert_eq!(cn, "tee.node1.dev.example.com-3f2a9c148b7d");
    }

    #[test]
    fn generated_common_name_uses_current_scheme_when_not_fqdn() {
        let uuid = Uuid::parse_str("3f2a9c14-8b7d-4e21-a9f0-1c2d3e4f5a6b").unwrap();
        let cn = generate_tee_common_name_from_hostname(Some("CVM_Prod.01"), uuid);
        assert_eq!(cn, "tas.cvm-prod-01-3f2a9c148b7d");
    }

    #[test]
    fn system_hostname_selects_fqdn_or_short_hostname_format() {
        let uuid = Uuid::parse_str("3f2a9c14-8b7d-4e21-a9f0-1c2d3e4f5a6b").unwrap();

        assert_eq!(
            generate_tee_common_name_from_system_hostname(Some("node1.example.com"), uuid),
            "tee.node1.example.com-3f2a9c148b7d"
        );
        assert_eq!(
            generate_tee_common_name_from_system_hostname(Some("node1"), uuid),
            "tas.node1-3f2a9c148b7d"
        );
    }

    #[test]
    fn system_hostname_falls_back_to_unknown() {
        let uuid = Uuid::parse_str("3f2a9c14-8b7d-4e21-a9f0-1c2d3e4f5a6b").unwrap();

        assert_eq!(
            generate_tee_common_name_from_system_hostname(None, uuid),
            "tas.unknown-3f2a9c148b7d"
        );
        assert_eq!(
            generate_tee_common_name_from_system_hostname(Some(""), uuid),
            "tas.unknown-3f2a9c148b7d"
        );
    }

    #[test]
    fn generated_common_name_falls_back_to_unknown() {
        let uuid = Uuid::parse_str("3f2a9c14-8b7d-4e21-a9f0-1c2d3e4f5a6b").unwrap();
        let cn = generate_tee_common_name_from_hostname(Some("////"), uuid);
        assert_eq!(cn, "tas.unknown-3f2a9c148b7d");
    }

    #[test]
    fn generated_common_names_have_distinct_suffixes() {
        let first = generate_tee_common_name();
        let second = generate_tee_common_name();
        assert_ne!(first, second);
        assert!(first.starts_with("tee.") || first.starts_with("tas."));
        assert!(second.starts_with("tee.") || second.starts_with("tas."));
    }

    #[test]
    fn parse_san_accepts_each_type() {
        assert_eq!(
            parse_san("DNS:web.example.com").unwrap(),
            SanEntry::Dns("web.example.com".to_string())
        );
        assert_eq!(
            parse_san("uri:spiffe://td/x").unwrap(),
            SanEntry::Uri("spiffe://td/x".to_string())
        );
        assert_eq!(
            parse_san("Email:a@example.com").unwrap(),
            SanEntry::Email("a@example.com".to_string())
        );
        assert_eq!(
            parse_san("IP:10.0.0.1").unwrap(),
            SanEntry::Ip("10.0.0.1".parse().unwrap())
        );
    }

    #[test]
    fn parse_san_handles_ipv6_first_colon_split() {
        assert_eq!(
            parse_san("IP:2001:db8::1").unwrap(),
            SanEntry::Ip("2001:db8::1".parse().unwrap())
        );
    }

    #[test]
    fn parse_san_rejects_bad_inputs() {
        assert!(parse_san("nocolon").is_err());
        assert!(parse_san("DNS:").is_err());
        assert!(parse_san("IP:not-an-ip").is_err());
        assert!(parse_san("FOO:bar").is_err());
        assert!(parse_san("DNS:has space").is_err());
    }

    #[test]
    fn parse_common_name_validates() {
        assert_eq!(parse_common_name("  tee.node  ").unwrap(), "tee.node");
        assert!(parse_common_name("").is_err());
        assert!(parse_common_name("evil,O=other").is_err());
        assert!(parse_common_name("a=b").is_err());
        assert!(parse_common_name(&"x".repeat(65)).is_err());
    }

    #[test]
    fn builds_plain_pem_csr() {
        let key = AgentKey::generate(crate::certify::keygen::KeyAlgorithm::Rsa4096).unwrap();
        let cn = generate_tee_common_name_from_fqdn(
            Some("node1.dev.example.com"),
            Uuid::parse_str("3f2a9c14-8b7d-4e21-a9f0-1c2d3e4f5a6b").unwrap(),
        );
        let pem = build_plain_csr(&key, &cn, &[]).unwrap();

        assert!(pem.starts_with("-----BEGIN CERTIFICATE REQUEST-----"));
        let csr = CertReq::from_pem(&pem).unwrap();
        assert!(csr.info.attributes.is_empty());
        assert!(csr.info.subject.to_string().contains(&cn));

        let public_key_der = csr.info.public_key.to_der().unwrap();
        let public_key_ref = SubjectPublicKeyInfoRef::try_from(public_key_der.as_slice()).unwrap();
        let verifying_key = VerifyingKey::<sha2::Sha256>::try_from(public_key_ref).unwrap();
        let signature = Signature::try_from(csr.signature.raw_bytes()).unwrap();
        verifying_key
            .verify(&csr.info.to_der().unwrap(), &signature)
            .unwrap();
    }

    #[test]
    fn builds_csr_with_sans_embeds_values_and_verifies() {
        let key = AgentKey::generate(crate::certify::keygen::KeyAlgorithm::Rsa4096).unwrap();
        let sans = vec![
            SanEntry::Dns("web.example.com".to_string()),
            SanEntry::Uri("spiffe://td/x".to_string()),
            SanEntry::Ip("10.0.0.1".parse().unwrap()),
        ];
        let pem = build_plain_csr(&key, "tee.test", &sans).unwrap();
        let csr = CertReq::from_pem(&pem).unwrap();

        assert!(!csr.info.attributes.is_empty());

        let der = csr.info.to_der().unwrap();
        assert!(contains_subslice(&der, b"web.example.com"));
        assert!(contains_subslice(&der, b"spiffe://td/x"));
        assert!(contains_subslice(&der, &[10u8, 0, 0, 1]));

        let public_key_der = csr.info.public_key.to_der().unwrap();
        let public_key_ref = SubjectPublicKeyInfoRef::try_from(public_key_der.as_slice()).unwrap();
        let verifying_key = VerifyingKey::<sha2::Sha256>::try_from(public_key_ref).unwrap();
        let signature = Signature::try_from(csr.signature.raw_bytes()).unwrap();
        verifying_key
            .verify(&csr.info.to_der().unwrap(), &signature)
            .unwrap();
    }

    #[test]
    fn builds_csr_with_multiple_same_type_sans() {
        let key = AgentKey::generate(crate::certify::keygen::KeyAlgorithm::Rsa4096).unwrap();
        let sans = vec![
            SanEntry::Ip("10.0.0.1".parse().unwrap()),
            SanEntry::Ip("10.0.0.2".parse().unwrap()),
            SanEntry::Dns("a.example.com".to_string()),
            SanEntry::Dns("b.example.com".to_string()),
        ];
        let pem = build_plain_csr(&key, "tee.test", &sans).unwrap();
        let csr = CertReq::from_pem(&pem).unwrap();
        let der = csr.info.to_der().unwrap();

        // Both IP-type SANs are present (encoded as raw 4-octet addresses).
        assert!(contains_subslice(&der, &[10u8, 0, 0, 1]));
        assert!(contains_subslice(&der, &[10u8, 0, 0, 2]));
        // Both DNS-type SANs are present.
        assert!(contains_subslice(&der, b"a.example.com"));
        assert!(contains_subslice(&der, b"b.example.com"));
    }
}
