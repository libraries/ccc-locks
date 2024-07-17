use crate::error::Error;
use alloc::{string::String, vec::Vec};
use ckb_lock_helper::{
    constant::{BTC_PREFIX, PREFIX, SUFFIX},
    generate_sighash_all,
};
use ckb_std::{
    ckb_constants::Source,
    high_level::{load_script, load_witness_args},
};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

pub fn entry() -> Result<(), Error> {
    let script = load_script()?;
    let pubkey_hash = script.args().raw_data();
    if pubkey_hash.len() != 20 {
        return Err(Error::WrongPubkeyHash);
    }

    let mut to_be_hashed: Vec<u8> = Default::default();
    assert_eq!(BTC_PREFIX.len(), 24);
    to_be_hashed.push(BTC_PREFIX.len() as u8);
    to_be_hashed.extend(BTC_PREFIX.as_bytes());

    let sighash_all = generate_sighash_all()?;
    let sighash_all_hex = hex::encode(&sighash_all);
    let message1 = String::from(PREFIX) + &sighash_all_hex + SUFFIX;

    assert!(message1.len() < 256);
    to_be_hashed.push(message1.len() as u8);
    to_be_hashed.extend(message1.into_bytes());

    // Double SHA-256 from bitcoin
    let msg = Sha256::digest(&Sha256::digest(&to_be_hashed));

    let witness_args = load_witness_args(0, Source::GroupInput)?;
    let sig = witness_args
        .lock()
        .to_opt()
        .ok_or(Error::WrongSignatureFormat)?
        .raw_data();

    if sig.len() != 65 {
        return Err(Error::WrongSignatureFormat);
    }
    let rec_id = match sig[0] {
        31 | 32 | 33 | 34 => sig[0] - 31,
        39 | 40 | 41 | 42 => sig[0] - 39,
        _ => sig[0],
    };
    let rec_id = RecoveryId::try_from(rec_id).map_err(|_| Error::InvalidRecoverId)?;
    let signature = Signature::from_slice(&sig[1..]).map_err(|_| Error::WrongSignatureFormat)?;
    let recovered_key = VerifyingKey::recover_from_prehash(&msg, &signature, rec_id)
        .map_err(|_| Error::CanNotRecover)?;
    // TODO: double check its format
    let recovered_key_bytes = recovered_key.to_sec1_bytes();
    // RIPEMD160 over SHA-256 for pubkey hashing
    let pubkey_hash_result: [u8; 20] =
        Ripemd160::digest(&Sha256::digest(&recovered_key_bytes)).into();
    if pubkey_hash_result.as_ref() != pubkey_hash.as_ref() {
        return Err(Error::PubkeyHashMismatched);
    }
    Ok(())
}
