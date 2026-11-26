use std::net::IpAddr;
use x509_parser::prelude::{GeneralName, X509Certificate, parse_x509_certificate};
use x509_parser::public_key::PublicKey;

fn matches_host(name: &GeneralName<'_>, host: &str) -> bool {
    match (name, host.parse::<IpAddr>()) {
        (GeneralName::IPAddress(bytes), Ok(IpAddr::V4(ip))) => *bytes == ip.octets(),
        (GeneralName::IPAddress(bytes), Ok(IpAddr::V6(ip))) => *bytes == ip.octets(),
        (GeneralName::DNSName(dns), Err(_)) => dns.trim_end_matches('.').eq_ignore_ascii_case(host),
        _ => false,
    }
}

pub(crate) fn application_certificate<'a>(
    der: &'a [u8],
    uri: &str,
    server_host: Option<&str>,
    require_current: bool,
) -> Result<X509Certificate<'a>, &'static str> {
    if uri.is_empty()
        || uri.len() > 2048
        || uri.chars().any(char::is_control)
        || uri.bytes().any(|b| !b.is_ascii_graphic())
    {
        return Err("expected a nonempty ASCII application URI up to 2048 bytes");
    }
    let Ok(([], cert)) = parse_x509_certificate(der) else {
        return Err("expected one DER-encoded application certificate");
    };
    if require_current && !cert.validity().is_valid() {
        return Err("application certificate expired or is not yet valid");
    }
    if !matches!(cert.public_key().parsed(), Ok(PublicKey::RSA(ref rsa)) if (2048..=4096).contains(&rsa.key_size()))
    {
        return Err("the selected RSA channel policy requires a 2048–4096-bit RSA certificate");
    }

    let san = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .ok_or("expected one subject alternative name extension")?;
    let mut uris = san
        .value
        .general_names
        .iter()
        .filter_map(|name| match name {
            GeneralName::URI(value) => Some(*value),
            _ => None,
        });
    if uris.next() != Some(uri) || uris.next().is_some() {
        return Err("certificate SAN must contain the expected application URI exactly once");
    }
    if server_host.is_some_and(|host| {
        !san.value
            .general_names
            .iter()
            .any(|name| matches_host(name, host))
    }) {
        return Err("endpoint host differs from the pinned server certificate SAN");
    }
    let suitable_key = cert.key_usage().ok().flatten().is_some_and(|usage| {
        let key = usage.value;
        key.digital_signature()
            && key.non_repudiation()
            && key.key_encipherment()
            && key.data_encipherment()
    });
    let suitable_role = cert
        .extended_key_usage()
        .ok()
        .flatten()
        .is_some_and(|usage| {
            if server_host.is_some() {
                usage.value.server_auth
            } else {
                usage.value.client_auth
            }
        });
    if !suitable_key || !suitable_role {
        return Err("certificate KeyUsage or ExtendedKeyUsage is unsuitable for its role");
    }
    Ok(cert)
}
