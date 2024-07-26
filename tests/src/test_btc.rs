use crate::common::{assert_script_error, generate_sighash_all, println_hex, ripemd160_sha256, sha256_sha256};
use crate::core::{Pickaxer, Resource, Verifier};
use base64::Engine;
use ckb_types::prelude::{Builder, Entity, Pack};

static BINARY_CCC_LOCK_BTC: &[u8] = include_bytes!("../../build/release/ccc-btc-lock");

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

fn message_sign(msg: &str, prikey: &k256::ecdsa::SigningKey) -> [u8; 65] {
    let m = message_hash(msg);
    let sigrec = prikey.sign_prehash_recoverable(&m).unwrap();
    let mut r = [0u8; 65];
    r[0] = sigrec.1.to_byte();
    r[1..65].copy_from_slice(&sigrec.0.to_vec());
    r
}

fn default_tx(dl: &mut Resource, px: &mut Pickaxer) -> ckb_types::core::TransactionView {
    let tx_builder = ckb_types::core::TransactionBuilder::default();
    // Create prior knowledge
    let prikey_byte: [u8; 32] =
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let prikey = k256::ecdsa::SigningKey::from_slice(&prikey_byte).unwrap();
    let pubkey = prikey.verifying_key();
    let pubkey_hash = ripemd160_sha256(&pubkey.to_sec1_bytes());
    println_hex("pubkey_hash_expect", &pubkey_hash);
    // Create cell meta
    let cell_meta_ccc_lock_btc = px.insert_cell_data(dl, BINARY_CCC_LOCK_BTC);
    let cell_meta_i =
        px.insert_cell_fund(dl, px.create_script_by_type(&cell_meta_ccc_lock_btc, &pubkey_hash), None, &[]);
    // Create cell dep
    let tx_builder = tx_builder.cell_dep(px.create_cell_dep(&cell_meta_ccc_lock_btc));
    // Create input
    let tx_builder = tx_builder.input(px.create_cell_input(&cell_meta_i));
    // Create output
    let tx_builder =
        tx_builder.output(px.create_cell_output(px.create_script_by_type(&cell_meta_ccc_lock_btc, &pubkey_hash), None));
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
    let sig = message_sign(&sighash_all_hex, &prikey);
    let tx_builder = tx_builder.set_witnesses(vec![ckb_types::packed::WitnessArgs::new_builder()
        .lock(Some(ckb_types::bytes::Bytes::copy_from_slice(&sig)).pack())
        .build()
        .as_bytes()
        .pack()]);
    tx_builder.build()
}

#[test]
fn test_success() {
    let mut dl = Resource::default();
    let mut px = Pickaxer::default();
    let tx = default_tx(&mut dl, &mut px);
    let tx_resolved =
        ckb_types::core::cell::resolve_transaction(tx, &mut std::collections::HashSet::new(), &dl, &dl).unwrap();
    let verifier = Verifier::default();
    verifier.verify(&tx_resolved, &dl).unwrap();
}

#[test]
fn test_success_recid_add_31() {
    let mut dl = Resource::default();
    let mut px = Pickaxer::default();
    let tx = default_tx(&mut dl, &mut px);

    let wa = ckb_types::packed::WitnessArgs::new_unchecked(tx.witnesses().get_unchecked(0).raw_data());
    let mut wa_lock = wa.lock().to_opt().unwrap().raw_data().to_vec();
    wa_lock[0] += 31;
    let wa = wa.as_builder().lock(Some(ckb_types::bytes::Bytes::from(wa_lock)).pack()).build();
    let tx = tx.as_advanced_builder().set_witnesses(vec![wa.as_bytes().pack()]).build();

    let tx_resolved =
        ckb_types::core::cell::resolve_transaction(tx, &mut std::collections::HashSet::new(), &dl, &dl).unwrap();
    let verifier = Verifier::default();
    verifier.verify(&tx_resolved, &dl).unwrap();
}

#[test]
fn test_success_recid_add_39() {
    let mut dl = Resource::default();
    let mut px = Pickaxer::default();
    let tx = default_tx(&mut dl, &mut px);

    let wa = ckb_types::packed::WitnessArgs::new_unchecked(tx.witnesses().get_unchecked(0).raw_data());
    let mut wa_lock = wa.lock().to_opt().unwrap().raw_data().to_vec();
    wa_lock[0] += 39;
    let wa = wa.as_builder().lock(Some(ckb_types::bytes::Bytes::from(wa_lock)).pack()).build();
    let tx = tx.as_advanced_builder().set_witnesses(vec![wa.as_bytes().pack()]).build();

    let tx_resolved =
        ckb_types::core::cell::resolve_transaction(tx, &mut std::collections::HashSet::new(), &dl, &dl).unwrap();
    let verifier = Verifier::default();
    verifier.verify(&tx_resolved, &dl).unwrap();
}

#[test]
fn test_failure_witness_args() {
    let mut dl = Resource::default();
    let mut px = Pickaxer::default();
    let tx = default_tx(&mut dl, &mut px);

    let wa = ckb_types::packed::WitnessArgs::new_unchecked(tx.witnesses().get_unchecked(0).raw_data());
    let wa = wa.as_builder().lock(ckb_types::packed::BytesOpt::new_builder().set(None).build()).build();
    let tx = tx.as_advanced_builder().set_witnesses(vec![wa.as_bytes().pack()]).build();

    let tx_resolved =
        ckb_types::core::cell::resolve_transaction(tx, &mut std::collections::HashSet::new(), &dl, &dl).unwrap();
    let verifier = Verifier::default();
    assert_script_error(verifier.verify(&tx_resolved, &dl).unwrap_err(), 31);
}

#[test]
fn test_failure_wrong_pubkey_hash() {
    let mut dl = Resource::default();
    let mut px = Pickaxer::default();
    let tx = default_tx(&mut dl, &mut px);

    let input_outpoint = tx.inputs().get_unchecked(0).previous_output();
    let input_meta = dl.cell.get_mut(&input_outpoint).unwrap();
    let input_cell_output = &input_meta.cell_output;
    let input_cell_output_script = input_cell_output.lock();
    let input_cell_output_script = input_cell_output_script.as_builder().args(vec![0u8; 19].pack()).build();
    let input_cell_output = input_cell_output.clone().as_builder().lock(input_cell_output_script).build();
    input_meta.cell_output = input_cell_output;

    let tx_resolved =
        ckb_types::core::cell::resolve_transaction(tx, &mut std::collections::HashSet::new(), &dl, &dl).unwrap();
    let verifier = Verifier::default();
    assert_script_error(verifier.verify(&tx_resolved, &dl).unwrap_err(), 32);
}

#[test]
fn test_failure_pubkey_hash_mismatched() {
    let mut dl = Resource::default();
    let mut px = Pickaxer::default();
    let tx = default_tx(&mut dl, &mut px);

    let input_outpoint = tx.inputs().get_unchecked(0).previous_output();
    let input_meta = dl.cell.get_mut(&input_outpoint).unwrap();
    let input_cell_output = &input_meta.cell_output;
    let input_cell_output_script = input_cell_output.lock();
    let input_cell_output_script = input_cell_output_script.as_builder().args(vec![0u8; 20].pack()).build();
    let input_cell_output = input_cell_output.clone().as_builder().lock(input_cell_output_script).build();
    input_meta.cell_output = input_cell_output;

    let tx_resolved =
        ckb_types::core::cell::resolve_transaction(tx, &mut std::collections::HashSet::new(), &dl, &dl).unwrap();
    let verifier = Verifier::default();
    assert_script_error(verifier.verify(&tx_resolved, &dl).unwrap_err(), 33);
}

#[test]
fn test_failure_sig_format() {
    let mut dl = Resource::default();
    let mut px = Pickaxer::default();
    let tx = default_tx(&mut dl, &mut px);

    let wa = ckb_types::packed::WitnessArgs::new_unchecked(tx.witnesses().get_unchecked(0).raw_data());
    let mut wa_lock = wa.lock().to_opt().unwrap().raw_data().to_vec();
    wa_lock[0x21..0x41].copy_from_slice(&vec![0u8; 32]);
    let wa = wa.as_builder().lock(Some(ckb_types::bytes::Bytes::from(wa_lock)).pack()).build();
    let tx = tx.as_advanced_builder().set_witnesses(vec![wa.as_bytes().pack()]).build();

    let tx_resolved =
        ckb_types::core::cell::resolve_transaction(tx, &mut std::collections::HashSet::new(), &dl, &dl).unwrap();
    let verifier = Verifier::default();
    assert_script_error(verifier.verify(&tx_resolved, &dl).unwrap_err(), 34);
}

#[test]
fn test_failure_recid() {
    let mut dl = Resource::default();
    let mut px = Pickaxer::default();
    let tx = default_tx(&mut dl, &mut px);

    let wa = ckb_types::packed::WitnessArgs::new_unchecked(tx.witnesses().get_unchecked(0).raw_data());
    let mut wa_lock = wa.lock().to_opt().unwrap().raw_data().to_vec();
    wa_lock[0] = 4;
    let wa = wa.as_builder().lock(Some(ckb_types::bytes::Bytes::from(wa_lock)).pack()).build();
    let tx = tx.as_advanced_builder().set_witnesses(vec![wa.as_bytes().pack()]).build();

    let tx_resolved =
        ckb_types::core::cell::resolve_transaction(tx, &mut std::collections::HashSet::new(), &dl, &dl).unwrap();
    let verifier = Verifier::default();
    assert_script_error(verifier.verify(&tx_resolved, &dl).unwrap_err(), 35);
}

#[test]
fn test_failure_can_not_recover() {
    let mut dl = Resource::default();
    let mut px = Pickaxer::default();
    let tx = default_tx(&mut dl, &mut px);

    let wa = ckb_types::packed::WitnessArgs::new_unchecked(tx.witnesses().get_unchecked(0).raw_data());
    let mut wa_lock = wa.lock().to_opt().unwrap().raw_data().to_vec();
    wa_lock[0] = 3 - wa_lock[0];
    let wa = wa.as_builder().lock(Some(ckb_types::bytes::Bytes::from(wa_lock)).pack()).build();
    let tx = tx.as_advanced_builder().set_witnesses(vec![wa.as_bytes().pack()]).build();

    let tx_resolved =
        ckb_types::core::cell::resolve_transaction(tx, &mut std::collections::HashSet::new(), &dl, &dl).unwrap();
    let verifier = Verifier::default();
    assert_script_error(verifier.verify(&tx_resolved, &dl).unwrap_err(), 36);
}

#[test]
fn test_success_e2e() {
    let mut dl = Resource::default();
    let mut px = Pickaxer::default();
    let tx = default_tx(&mut dl, &mut px);

    // 1. Install Unisat
    // 2. Import account with private key 0x0000000000000000000000000000000000000000000000000000000000000001
    // 3. Open F12
    // 4. Run await unisat.signMessage('Signing a CKB transaction: 0xff934206c421310835b280fd6c9efd98be590f429c2a27a195b
    //        9578bde426cd0\n\nIMPORTANT: Please verify the integrity and authenticity of connected BTC wallet before si
    //        gning this message\n')
    let wa = ckb_types::packed::WitnessArgs::new_unchecked(tx.witnesses().get_unchecked(0).raw_data());
    let mut wa_lock = wa.lock().to_opt().unwrap().raw_data().to_vec();
    wa_lock.copy_from_slice(
        &base64::prelude::BASE64_STANDARD
            .decode("IJIw4RokuCqaS6TBTqJSQWvWJuRRX+0opTmhY6vL88nSOWqULiOXaeZbCtQZJ8lHj3eYoz4+5w9sXrCr5/zfxHA=")
            .unwrap(),
    );
    let wa = wa.as_builder().lock(Some(ckb_types::bytes::Bytes::from(wa_lock)).pack()).build();
    let tx = tx.as_advanced_builder().set_witnesses(vec![wa.as_bytes().pack()]).build();

    let tx_resolved =
        ckb_types::core::cell::resolve_transaction(tx, &mut std::collections::HashSet::new(), &dl, &dl).unwrap();
    let verifier = Verifier::default();
    verifier.verify(&tx_resolved, &dl).unwrap();
}
