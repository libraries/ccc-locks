use crate::core::Resource;
use ckb_types::prelude::{Entity, Unpack};
use sha2::Digest;

pub fn assert_script_error(err: ckb_error::Error, err_code: i8) {
    let error_string = err.to_string();
    assert!(
        error_string.contains(format!("error code {}", err_code).as_str()),
        "error_string: {}, expected_error_code: {}",
        error_string,
        err_code
    );
}

pub fn blake2b(data: &[u8]) -> [u8; 32] {
    let mut blake2b = blake2b_ref::Blake2bBuilder::new(32)
        .personal(b"ckb-default-hash")
        .build();
    let mut hash = [0u8; 32];
    blake2b.update(data);
    blake2b.finalize(&mut hash);
    hash
}

pub fn println_hex(name: &str, data: &[u8]) {
    println!(
        "Tester(........): {}(len={}): {}",
        name,
        data.len(),
        hex::encode(data)
    );
}

pub fn println_log(data: &str) {
    println!("Tester(........): {}", data);
}

pub fn println_rtx(tx_resolved: &ckb_types::core::cell::ResolvedTransaction) {
    let tx_json = ckb_jsonrpc_types::TransactionView::from(tx_resolved.transaction.clone());
    println!(
        "Tester(........): {}",
        serde_json::to_string_pretty(&tx_json).unwrap()
    );
}

pub fn ripemd160(message: &[u8]) -> [u8; 20] {
    let mut hasher = ripemd::Ripemd160::new();
    hasher.update(message);
    hasher.finalize().into()
}

pub fn ripemd160_sha256(msg: &[u8]) -> [u8; 20] {
    ripemd160(&sha256(msg))
}

pub fn sha256(msg: &[u8]) -> [u8; 32] {
    let mut hasher = sha2::Sha256::new();
    hasher.update(msg);
    hasher.finalize().into()
}

pub fn sha256_sha256(msg: &[u8]) -> [u8; 32] {
    sha256(&sha256(msg))
}

pub fn generate_sighash_all(
    tx: &ckb_types::core::TransactionView,
    dl: &Resource,
    i: usize,
) -> [u8; 32] {
    let mut sighash_all_data: Vec<u8> = vec![];
    sighash_all_data.extend(&tx.hash().raw_data());
    let input_major_outpoint = &tx.inputs().get_unchecked(i).previous_output();
    let input_major = &dl.cell.get(input_major_outpoint).unwrap().cell_output;
    for input in tx.input_pts_iter().take(i) {
        let input = &dl.cell.get(&input).unwrap().cell_output;
        assert_ne!(input_major.lock(), input.lock());
    }
    let witness: ckb_types::bytes::Bytes = tx.witnesses().get_unchecked(i).unpack();
    let witness_len = witness.len() as u64;
    sighash_all_data.extend(&witness_len.to_le_bytes());
    sighash_all_data.extend(&witness);
    for input in tx.input_pts_iter().skip(i + 1) {
        let input = &dl.cell.get(&input).unwrap().cell_output;
        if input_major.lock() == input.lock() {
            let witness = tx.witnesses().get_unchecked(i);
            let witness_len = witness.len() as u64;
            sighash_all_data.extend(&witness_len.to_le_bytes());
            sighash_all_data.extend(&witness.as_bytes());
        }
    }
    for witness in tx.witnesses().into_iter().skip(tx.inputs().len()) {
        let witness_len = witness.len() as u64;
        sighash_all_data.extend(&witness_len.to_le_bytes());
        sighash_all_data.extend(&witness.as_bytes());
    }
    println_log(&format!(
        "hashed {} bytes in sighash_all",
        sighash_all_data.len()
    ));
    let sighash_all = blake2b(&sighash_all_data);
    println_hex("sighash_all", &sighash_all);
    sighash_all
}
