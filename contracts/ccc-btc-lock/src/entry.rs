use crate::error::Error;
use alloc::vec::Vec;
use ckb_lock_helper::{generate_sighash_all, println_hex};
use ckb_std::{
    ckb_constants::Source,
    high_level::{load_script, load_witness_args},
};
use ripemd::{Digest, Ripemd160};
use secp256k1::ffi::types::AlignedType;
use secp256k1::{self, ecdsa, Message, Secp256k1};
use sha2::Sha256;

fn ripemd160_sha256(msg: &[u8]) -> [u8; 20] {
    ripemd160(&sha256(msg))
}

fn ripemd160(message: &[u8]) -> [u8; 20] {
    let mut hasher = Ripemd160::new();
    hasher.update(message);
    hasher.finalize().into()
}

fn sha256(msg: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(msg);
    hasher.finalize().into()
}

fn sha256_sha256(msg: &[u8]) -> [u8; 32] {
    sha256(&sha256(msg))
}

fn message_hash(msg: &str) -> [u8; 32] {
    // Only 32-bytes hex representation of the hash is allowed.
    assert_eq!(msg.len(), 64);
    // Text used to signify that a signed message follows and to prevent inadvertently signing a transaction.
    const CKB_PREFIX: &str = "Signing a CKB transaction: 0x";
    const CKB_SUFFIX: &str = "\n\nIMPORTANT: Please verify the integrity and authenticity of connected BTC wallet before signing this message\n";
    const BTC_PREFIX: &str = "Bitcoin Signed Message:\n";
    let mut data: Vec<u8> = Vec::new();
    assert_eq!(BTC_PREFIX.len(), 24);
    data.push(24);
    data.extend(BTC_PREFIX.as_bytes());
    data.push((CKB_PREFIX.len() + msg.len() + CKB_SUFFIX.len()) as u8);
    data.extend(CKB_PREFIX.as_bytes());
    data.extend(msg.as_bytes());
    data.extend(CKB_SUFFIX.as_bytes());
    sha256_sha256(&data)
}

pub fn entry() -> Result<(), Error> {
    let script = load_script()?;
    let pubkey_hash_expect = script.args().raw_data();
    if pubkey_hash_expect.len() != 20 {
        return Err(Error::WrongPubkeyHash);
    }
    let sighash_all = generate_sighash_all()?;
    let sighash_all_hex = hex::encode(&sighash_all);
    let digest_hash = message_hash(&sighash_all_hex);
    let witness_args = load_witness_args(0, Source::GroupInput)?;
    let sig_raw = witness_args
        .lock()
        .to_opt()
        .ok_or(Error::WrongSignatureFormat)?
        .raw_data();
    if sig_raw.len() != 65 {
        return Err(Error::WrongSignatureFormat);
    }
    let rec_id = match sig_raw[0] {
        31 | 32 | 33 | 34 => sig_raw[0] - 31,
        39 | 40 | 41 | 42 => sig_raw[0] - 39,
        _ => sig_raw[0],
    };

    let mut secp_buf = [AlignedType::zeroed(); 70_000];
    let secp = Secp256k1::preallocated_new(&mut secp_buf).unwrap();
    let pubkey_result = secp
        .recover_ecdsa(
            &Message::from_digest_slice(&digest_hash).unwrap(),
            &ecdsa::RecoverableSignature::from_compact(
                &sig_raw[1..],
                ecdsa::RecoveryId::from_i32(rec_id as i32).map_err(|_| Error::InvalidRecoverId)?,
            )
            .unwrap(),
        )
        .map_err(|_| Error::CanNotRecover)?
        .serialize();
    assert!(pubkey_result.len() == 33);
    let pubkey_hash_result = ripemd160_sha256(&pubkey_result);
    println_hex("pubkey_hash_result", pubkey_hash_result.as_ref());
    println_hex("pubkey_hash_expect", pubkey_hash_expect.as_ref());
    if pubkey_hash_result.as_ref() != pubkey_hash_expect.as_ref() {
        return Err(Error::PubkeyHashMismatched);
    }
    Ok(())
}
