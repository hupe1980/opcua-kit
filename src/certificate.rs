use std::net::IpAddr;
use x509_parser::prelude::{GeneralName, X509Certificate, X509Version, parse_x509_certificate};
use x509_parser::public_key::PublicKey;

fn matches_host(name: &GeneralName<'_>, host: &str) -> bool {
    match (name, host.parse::<IpAddr>()) {
        (GeneralName::IPAddress(bytes), Ok(IpAddr::V4(ip))) => *bytes == ip.octets(),
        (GeneralName::IPAddress(bytes), Ok(IpAddr::V6(ip))) => *bytes == ip.octets(),
        (GeneralName::DNSName(dns), Err(_)) => dns.trim_end_matches('.').eq_ignore_ascii_case(host),
        _ => false,
    }
}

fn uri_from_names<'a>(names: &[GeneralName<'a>]) -> Result<&'a str, &'static str> {
    let mut uris = names.iter().filter_map(|name| match name {
        GeneralName::URI(value) => Some(*value),
        _ => None,
    });
    let uri = uris
        .next()
        .ok_or("certificate SAN has no application URI")?;
    if uris.next().is_some() {
        return Err("certificate SAN must have exactly one application URI");
    }
    let valid_scheme = uri.split_once(':').is_some_and(|(scheme, rest)| {
        !rest.is_empty()
            && scheme
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphabetic)
            && scheme
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
    });
    if !valid_scheme || uri.len() > 2048 || uri.bytes().any(|b| !b.is_ascii_graphic()) {
        return Err("expected an absolute ASCII application URI up to 2048 bytes");
    }
    Ok(uri)
}

/// Read the single application URI from a DER certificate's subject alternative name.
/// Certificate validity, usage and peer trust are checked when preparing a connection.
#[cfg(feature = "client")]
pub fn certificate_application_uri(der: &[u8]) -> Result<&str, crate::ConnectError> {
    use crate::ConnectError::InvalidConfiguration;
    if der.len() > 64 * 1024 {
        return Err(InvalidConfiguration("certificate exceeds 64 KiB"));
    }
    let Ok(([], cert)) = parse_x509_certificate(der) else {
        return Err(InvalidConfiguration(
            "expected one DER-encoded application certificate",
        ));
    };
    let san = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .ok_or(InvalidConfiguration(
            "expected one subject alternative name extension",
        ))?;
    uri_from_names(&san.value.general_names).map_err(InvalidConfiguration)
}

pub(crate) fn application_certificate<'a>(
    der: &'a [u8],
    uri: &str,
    server_host: Option<&str>,
    require_current: bool,
) -> Result<X509Certificate<'a>, &'static str> {
    let Ok(([], cert)) = parse_x509_certificate(der) else {
        return Err("expected one DER-encoded application certificate");
    };
    if cert.version() != X509Version::V3
        || !cert
            .basic_constraints()
            .ok()
            .flatten()
            .is_some_and(|bc| !bc.value.ca && bc.value.path_len_constraint.is_none())
    {
        return Err("expected an X.509 v3 application leaf with BasicConstraints CA=false");
    }
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
    if uri_from_names(&san.value.general_names)? != uri {
        return Err("certificate SAN differs from the expected application URI");
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn application_uri_is_absolute_and_unambiguous() {
        for expected in [
            "urn:fixture:client",
            "https://site.example/app",
            "x+v1.2-a:test",
        ] {
            assert_eq!(uri_from_names(&[GeneralName::URI(expected)]), Ok(expected));
        }
        for invalid in [
            "client",
            "urn:",
            ":client",
            "1app:client",
            "a_b:c",
            "urn:field kit",
        ] {
            assert!(uri_from_names(&[GeneralName::URI(invalid)]).is_err());
        }
        assert!(uri_from_names(&[GeneralName::DNSName("site.example")]).is_err());
        assert!(
            uri_from_names(&[GeneralName::URI("urn:app:a"), GeneralName::URI("urn:app:b")])
                .is_err()
        );
    }
}
