//! OPC UA Part 6 UASC SignAndEncrypt message chunks.

/// Security policy for a SignAndEncrypt secure channel.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum SecurityPolicy {
    /// Widely supported RSA policy.
    #[default]
    Basic256Sha256,
    /// RSA-OAEP key exchange with AES-128 symmetric encryption.
    Aes128Sha256RsaOaep,
    /// RSA-PSS signatures with AES-256 symmetric encryption.
    Aes256Sha256RsaPss,
}

impl SecurityPolicy {
    /// OPC UA policy URI for endpoint selection.
    pub const fn uri(self) -> &'static str {
        match self {
            Self::Basic256Sha256 => "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256",
            Self::Aes128Sha256RsaOaep => {
                "http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep"
            }
            Self::Aes256Sha256RsaPss => {
                "http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss"
            }
        }
    }
}

use crate::ua::StatusCode;
use aes::{Aes128, Aes256};
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::NoPadding};
use hmac::{Hmac, Mac};
use rsa::{
    PrivateKey, PublicKey,
    pkcs1::DecodeRsaPrivateKey,
    pkcs8::{DecodePrivateKey, DecodePublicKey},
    traits::PublicKeyParts,
};
use sha1::{Digest, Sha1};
use x509_parser::{
    certificate::Validity,
    prelude::{FromDer, X509Certificate},
};
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, StatusCode>;
type Hmac256 = Hmac<sha2::Sha256>;
const SECURITY: StatusCode = StatusCode::BadSecurityChecksFailed;

impl SecurityPolicy {
    pub(crate) fn signature_uri(self) -> &'static str {
        match self {
            Self::Aes256Sha256RsaPss => "http://opcfoundation.org/UA/security/rsa-pss-sha2-256",
            _ => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        }
    }

    #[cfg(feature = "client")]
    pub(crate) fn encryption_uri(self) -> &'static str {
        match self {
            Self::Aes256Sha256RsaPss => "http://opcfoundation.org/UA/security/rsa-oaep-sha2-256",
            _ => "http://www.w3.org/2001/04/xmlenc#rsa-oaep",
        }
    }

    fn rsa_payload(self, modulus: usize) -> usize {
        modulus
            - if self == Self::Aes256Sha256RsaPss {
                66
            } else {
                42
            }
    }
}

pub(crate) fn nonce() -> Result<[u8; 32]> {
    let mut result = [0; 32];
    getrandom::fill(&mut result).map_err(|_| SECURITY)?;
    Ok(result)
}

pub(crate) struct Peer {
    pub(crate) der: Vec<u8>,
    key: PublicKey,
    validity: Validity,
}

impl Peer {
    pub(crate) fn new(der: &[u8]) -> Result<Self> {
        let (rest, cert) = X509Certificate::from_der(der).map_err(|_| SECURITY)?;
        let key = PublicKey::from_public_key_der(cert.public_key().raw).map_err(|_| SECURITY)?;
        if !rest.is_empty() || !(2048..=4096).contains(&key.n().bit_width()) {
            return Err(SECURITY);
        }
        Ok(Self {
            der: der.to_vec(),
            validity: cert.validity().clone(),
            key,
        })
    }

    pub(crate) fn verify(
        &self,
        policy: SecurityPolicy,
        data: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        match policy {
            SecurityPolicy::Aes256Sha256RsaPss => {
                self.key.pss_verify::<rsa::sha2::Sha256>(data, signature)
            }
            _ => self
                .key
                .pkcs1v15_verify::<rsa::sha2::Sha256>(data, signature),
        }
        .map_err(|_| SECURITY)
    }

    pub(crate) fn encrypt(&self, policy: SecurityPolicy, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut result = Vec::new();
        for block in plaintext.chunks(policy.rsa_payload(self.key.size())) {
            let ciphertext = match policy {
                SecurityPolicy::Aes256Sha256RsaPss => {
                    self.key.oaep_encrypt::<rsa::sha2::Sha256>(block)
                }
                _ => self.key.oaep_encrypt::<Sha1>(block),
            }
            .map_err(|_| SECURITY)?;
            result.extend(ciphertext);
        }
        Ok(result)
    }
}

pub(crate) struct Identity {
    pub(crate) der: Vec<u8>,
    key: PrivateKey,
    validity: Validity,
}

impl Identity {
    pub(crate) fn new(der: &[u8], private_key: &[u8]) -> Result<Self> {
        let peer = Peer::new(der)?;
        let key = PrivateKey::from_pkcs8_der(private_key)
            .or_else(|_| PrivateKey::from_pkcs1_der(private_key))
            .map_err(|_| SECURITY)?;
        if key.to_public_key() != peer.key {
            return Err(SECURITY);
        }
        Ok(Self {
            der: peer.der,
            validity: peer.validity,
            key,
        })
    }

    pub(crate) fn sign(&self, policy: SecurityPolicy, data: &[u8]) -> Result<Vec<u8>> {
        match policy {
            SecurityPolicy::Aes256Sha256RsaPss => self.key.pss_sign::<rsa::sha2::Sha256>(data),
            _ => self.key.pkcs1v15_sign::<rsa::sha2::Sha256>(data),
        }
        .map_err(|_| SECURITY)
    }
}

pub(crate) struct Keys {
    signing: Zeroizing<Vec<u8>>,
    encryption: Zeroizing<Vec<u8>>,
    iv: Zeroizing<Vec<u8>>,
}

impl Keys {
    pub(crate) fn derive(policy: SecurityPolicy, secret: &[u8], seed: &[u8]) -> Result<Self> {
        if secret.len() != 32
            || seed.len() != 32
            || secret == seed
            || secret.iter().all(|&b| b == 0)
            || seed.iter().all(|&b| b == 0)
        {
            return Err(SECURITY);
        }
        let encryption_len = if policy == SecurityPolicy::Aes128Sha256RsaOaep {
            16
        } else {
            32
        };
        let prf = Hmac256::new_from_slice(secret).map_err(|_| SECURITY)?;
        let mut a = Zeroizing::new(seed.to_vec());
        let mut material = Zeroizing::new(Vec::new());
        while material.len() < 32 + encryption_len + 16 {
            *a = prf
                .clone()
                .chain_update(&a[..])
                .finalize()
                .into_bytes()
                .to_vec();
            material.extend(
                prf.clone()
                    .chain_update(&a[..])
                    .chain_update(seed)
                    .finalize()
                    .into_bytes(),
            );
        }
        Ok(Self {
            signing: Zeroizing::new(material[..32].to_vec()),
            encryption: Zeroizing::new(material[32..32 + encryption_len].to_vec()),
            iv: Zeroizing::new(material[32 + encryption_len..48 + encryption_len].to_vec()),
        })
    }

    fn hmac(&self, data: &[u8]) -> Result<Hmac256> {
        Ok(Hmac256::new_from_slice(&self.signing)
            .map_err(|_| SECURITY)?
            .chain_update(data))
    }
}

fn u32_at(bytes: &[u8], index: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        bytes
            .get(index..index + 4)
            .ok_or(SECURITY)?
            .try_into()
            .map_err(|_| SECURITY)?,
    ))
}

fn blob(data: &[u8], offset: &mut usize) -> Result<Vec<u8>> {
    let size = u32_at(data, *offset)? as usize;
    *offset += 4;
    let slice = data
        .get(*offset..offset.checked_add(size).ok_or(SECURITY)?)
        .ok_or(SECURITY)?;
    *offset += size;
    Ok(slice.to_vec())
}

fn put_blob(out: &mut Vec<u8>, data: &[u8]) -> Result<()> {
    out.extend(
        u32::try_from(data.len())
            .map_err(|_| SECURITY)?
            .to_le_bytes(),
    );
    out.extend(data);
    Ok(())
}

fn prefix(kind: [u8; 4], channel: u32) -> Vec<u8> {
    let mut out = kind.to_vec();
    out.extend([0; 4]);
    out.extend(channel.to_le_bytes());
    out
}

fn checked_frame(frame: &[u8]) -> Result<()> {
    if frame.len() < 16 || frame.len() != u32_at(frame, 4)? as usize {
        return Err(SECURITY);
    }
    Ok(())
}

fn set_size(header: &mut [u8], length: usize) -> Result<()> {
    header[4..8].copy_from_slice(&u32::try_from(length).map_err(|_| SECURITY)?.to_le_bytes());
    Ok(())
}

fn padded(seq: u32, req: u32, data: &[u8], block: usize, signature: usize, extra: bool) -> Vec<u8> {
    let mut plaintext = seq.to_le_bytes().to_vec();
    plaintext.extend(req.to_le_bytes());
    plaintext.extend(data);
    let padding =
        (block - ((plaintext.len() + signature + 1 + usize::from(extra)) % block)) % block;
    plaintext.resize(plaintext.len() + padding + 1, padding as u8);
    if extra {
        plaintext.push((padding >> 8) as u8);
    }
    plaintext
}

fn unpack(data: &[u8], extra: bool) -> Result<(u32, u32, Vec<u8>)> {
    let high = if extra {
        usize::from(*data.last().ok_or(SECURITY)?) << 8
    } else {
        0
    };
    let end = data.len().checked_sub(usize::from(extra)).ok_or(SECURITY)?;
    let low = *data
        .get(end.checked_sub(1).ok_or(SECURITY)?)
        .ok_or(SECURITY)?;
    let start = end
        .checked_sub(high + usize::from(low) + 1)
        .ok_or(SECURITY)?;
    if data[start..end].iter().any(|&byte| byte != low) {
        return Err(SECURITY);
    }
    Ok((
        u32_at(data, 0)?,
        u32_at(data, 4)?,
        data.get(8..start).ok_or(SECURITY)?.to_vec(),
    ))
}

fn valid_channel_certificates(local: &Identity, peer: &Peer) -> Result<()> {
    if local.validity.is_valid() && peer.validity.is_valid() {
        Ok(())
    } else {
        Err(StatusCode::BadCertificateTimeInvalid)
    }
}

pub(crate) fn protect_open(
    policy: SecurityPolicy,
    local: &Identity,
    peer: &Peer,
    channel: u32,
    seq: u32,
    req: u32,
    data: &[u8],
) -> Result<Vec<u8>> {
    valid_channel_certificates(local, peer)?;
    let mut header = prefix(*b"OPNF", channel);
    put_blob(&mut header, policy.uri().as_bytes())?;
    put_blob(&mut header, &local.der)?;
    put_blob(&mut header, &Sha1::digest(&peer.der))?;
    let block = policy.rsa_payload(peer.key.size());
    let plaintext = padded(
        seq,
        req,
        data,
        block,
        local.key.size(),
        peer.key.size() > 256,
    );
    let total = header.len() + (plaintext.len() + local.key.size()) / block * peer.key.size();
    set_size(&mut header, total)?;
    let mut signed = header.clone();
    signed.extend(plaintext);
    let signature = local.sign(policy, &signed)?;
    signed.extend(signature);
    let encrypted = peer.encrypt(policy, &signed[header.len()..])?;
    header.extend(encrypted);
    Ok(header)
}

pub(crate) fn unprotect_open(
    policy: SecurityPolicy,
    local: &Identity,
    peer: &Peer,
    frame: &[u8],
) -> Result<(u32, u32, u32, Vec<u8>)> {
    valid_channel_certificates(local, peer)?;
    checked_frame(frame)?;
    let mut offset = 12;
    if &frame[..4] != b"OPNF"
        || blob(frame, &mut offset)? != policy.uri().as_bytes()
        || !blob(frame, &mut offset)?.starts_with(&peer.der)
        || blob(frame, &mut offset)? != Sha1::digest(&local.der).as_slice()
    {
        return Err(SECURITY);
    }
    let ciphertext = &frame[offset..];
    if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(local.key.size()) {
        return Err(SECURITY);
    }
    let mut signed = frame[..offset].to_vec();
    for block in ciphertext.chunks_exact(local.key.size()) {
        let plain = match policy {
            SecurityPolicy::Aes256Sha256RsaPss => {
                local.key.oaep_decrypt::<rsa::sha2::Sha256>(block)
            }
            _ => local.key.oaep_decrypt::<Sha1>(block),
        }
        .map_err(|_| SECURITY)?;
        if plain.len() != policy.rsa_payload(local.key.size()) {
            return Err(SECURITY);
        }
        signed.extend(plain);
    }
    let split = signed
        .len()
        .checked_sub(peer.key.size())
        .filter(|&n| n >= offset)
        .ok_or(SECURITY)?;
    peer.verify(policy, &signed[..split], &signed[split..])?;
    let (seq, req, data) = unpack(&signed[offset..split], local.key.size() > 256)?;
    Ok((u32_at(frame, 8)?, seq, req, data))
}

pub(crate) fn protect_message(
    keys: &Keys,
    kind: [u8; 4],
    channel: u32,
    token: u32,
    seq: u32,
    req: u32,
    data: &[u8],
) -> Result<Vec<u8>> {
    let mut out = prefix(kind, channel);
    out.extend(token.to_le_bytes());
    out.extend(padded(seq, req, data, 16, 32, false));
    let total = out.len() + 32;
    set_size(&mut out, total)?;
    out.extend(keys.hmac(&out)?.finalize().into_bytes());
    let encrypted = &mut out[16..];
    let len = encrypted.len();
    if keys.encryption.len() == 16 {
        cbc::Encryptor::<Aes128>::new_from_slices(&keys.encryption, &keys.iv)
            .map_err(|_| SECURITY)?
            .encrypt_padded_mut::<NoPadding>(encrypted, len)
    } else {
        cbc::Encryptor::<Aes256>::new_from_slices(&keys.encryption, &keys.iv)
            .map_err(|_| SECURITY)?
            .encrypt_padded_mut::<NoPadding>(encrypted, len)
    }
    .map_err(|_| SECURITY)?;
    Ok(out)
}

pub(crate) fn unprotect_message(
    keys: &Keys,
    frame: &[u8],
) -> Result<(u32, u32, u32, u32, Vec<u8>)> {
    checked_frame(frame)?;
    let mut clear = frame.to_vec();
    let ciphertext = &mut clear[16..];
    if ciphertext.len() < 48 || !ciphertext.len().is_multiple_of(16) {
        return Err(SECURITY);
    }
    if keys.encryption.len() == 16 {
        cbc::Decryptor::<Aes128>::new_from_slices(&keys.encryption, &keys.iv)
            .map_err(|_| SECURITY)?
            .decrypt_padded_mut::<NoPadding>(ciphertext)
    } else {
        cbc::Decryptor::<Aes256>::new_from_slices(&keys.encryption, &keys.iv)
            .map_err(|_| SECURITY)?
            .decrypt_padded_mut::<NoPadding>(ciphertext)
    }
    .map_err(|_| SECURITY)?;
    let split = clear.len() - 32;
    keys.hmac(&clear[..split])?
        .verify_slice(&clear[split..])
        .map_err(|_| SECURITY)?;
    let (seq, req, body) = unpack(&clear[16..split], false)?;
    Ok((u32_at(frame, 8)?, u32_at(frame, 12)?, seq, req, body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p_sha256_matches_independent_hmac_vector() {
        let secret: Vec<u8> = (0..32).collect();
        let seed: Vec<u8> = (32..64).collect();
        let keys = Keys::derive(SecurityPolicy::Basic256Sha256, &secret, &seed).unwrap();
        let actual = keys
            .signing
            .iter()
            .chain(keys.encryption.iter())
            .chain(keys.iv.iter())
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        assert_eq!(
            actual,
            concat!(
                "b72593c43fee5fafa0256cd6bb904ff40c066a225db95f66dd744e20858a2220",
                "ddf75067e3d76ac714c08e24eabd85ff425d7f5fb25e6e083b94b174e29db89b",
                "c513e9172274d5ed54e52a3552901ae0"
            )
        );
    }

    #[test]
    fn chunk_authentication_binds_header_sequence_payload_and_direction() {
        for policy in [
            SecurityPolicy::Basic256Sha256,
            SecurityPolicy::Aes128Sha256RsaOaep,
            SecurityPolicy::Aes256Sha256RsaPss,
        ] {
            let outbound = Keys::derive(policy, &[1; 32], &[2; 32]).unwrap();
            let inbound = Keys::derive(policy, &[2; 32], &[1; 32]).unwrap();
            for len in 0..=32 {
                let body = vec![42; len];
                let frame = protect_message(&outbound, *b"MSGC", 1, 2, 3, 4, &body).unwrap();
                assert_eq!(
                    unprotect_message(&outbound, &frame).unwrap(),
                    (1, 2, 3, 4, body)
                );
                assert!(unprotect_message(&inbound, &frame).is_err());
                for index in [0, 3, 4, 8, 12, 16, frame.len() - 1] {
                    let mut changed = frame.clone();
                    changed[index] ^= 1;
                    assert!(unprotect_message(&outbound, &changed).is_err());
                }
            }
        }
    }
}
