use crate::core::{println_hex, println_log, Pickaxer, Resource, Verifier};
use ckb_types::prelude::{Builder, Entity, Pack, Unpack};
use sha2::Digest;

static BINARY_CCC_LOCK_BTC: &[u8] = include_bytes!("../../build/release/ccc-btc-lock");

fn blake2b(data: &[u8]) -> [u8; 32] {
    let mut blake2b = blake2b_ref::Blake2bBuilder::new(32)
        .personal(b"ckb-default-hash")
        .build();
    let mut hash = [0u8; 32];
    blake2b.update(data);
    blake2b.finalize(&mut hash);
    hash
}

fn ripemd160_sha256(msg: &[u8]) -> [u8; 20] {
    ripemd160(&sha256(msg))
}

fn ripemd160(message: &[u8]) -> [u8; 20] {
    let mut hasher = ripemd::Ripemd160::new();
    hasher.update(message);
    hasher.finalize().into()
}

fn sha256(msg: &[u8]) -> [u8; 32] {
    let mut hasher = sha2::Sha256::new();
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
    pub const CKB_PREFIX: &str = "Signing a CKB transaction: 0x";
    pub const CKB_SUFFIX: &str = "\n\nIMPORTANT: Please verify the integrity and authenticity of connected BTC wallet before signing this message\n";
    pub const BTC_PREFIX: &str = "Bitcoin Signed Message:\n";
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

fn message_sign(msg: &str, prikey: k256::ecdsa::SigningKey) -> [u8; 65] {
    let m = message_hash(msg);
    let sigrec = prikey.sign_prehash_recoverable(&m).unwrap();
    let mut r = [0u8; 65];
    r[0] = sigrec.1.to_byte();
    r[1..65].copy_from_slice(&sigrec.0.to_vec());
    r
}

fn generate_sighash_all(
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

#[test]
fn test_success() {
    let mut dl = Resource::default();
    let mut px = Pickaxer::default();
    let tx_builder = ckb_types::core::TransactionBuilder::default();

    // Create prior knowledge
    let prikey_byte: [u8; 32] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 1,
    ];
    let prikey = k256::ecdsa::SigningKey::from_slice(&prikey_byte).unwrap();
    let pubkey = prikey.verifying_key();
    let pubkey_hash = ripemd160_sha256(&pubkey.to_sec1_bytes());
    println_hex("pubkey_hash_expect", &pubkey_hash);

    // Create cell meta
    let cell_meta_ccc_lock_btc = px.insert_cell_data(&mut dl, BINARY_CCC_LOCK_BTC);
    let cell_meta_i = px.insert_cell_fund(
        &mut dl,
        px.create_script(&cell_meta_ccc_lock_btc, &pubkey_hash),
        None,
        &[],
    );
    // Create cell dep
    let tx_builder = tx_builder.cell_dep(px.create_cell_dep(&cell_meta_ccc_lock_btc));
    // Create input
    let tx_builder = tx_builder.input(px.create_cell_input(&cell_meta_i));
    // Create output
    let tx_builder = tx_builder.output(px.create_cell_output(
        px.create_script(&cell_meta_ccc_lock_btc, &pubkey_hash),
        None,
    ));
    // Create output data
    let tx_builder = tx_builder.output_data(ckb_types::packed::Bytes::default());
    // Create witness
    let tx_builder = tx_builder.set_witnesses(vec![ckb_types::packed::WitnessArgs::new_builder()
        .lock(Some(ckb_types::bytes::Bytes::from(vec![0u8; 65])).pack())
        .build()
        .as_bytes()
        .pack()]);
    let sighash_all = generate_sighash_all(&tx_builder.clone().build(), &dl, 0);
    let sighash_all_hex = hex::encode(&sighash_all);
    let sig = message_sign(&sighash_all_hex, prikey);
    let tx_builder = tx_builder.set_witnesses(vec![ckb_types::packed::WitnessArgs::new_builder()
        .lock(Some(ckb_types::bytes::Bytes::copy_from_slice(&sig)).pack())
        .build()
        .as_bytes()
        .pack()]);

    // Verify transaction
    let tx = tx_builder.build();
    let tx_resolved = ckb_types::core::cell::resolve_transaction(
        tx,
        &mut std::collections::HashSet::new(),
        &dl,
        &dl,
    )
    .unwrap();
    let verifier = Verifier::default();
    verifier.verify(&tx_resolved, &dl).unwrap();
}
