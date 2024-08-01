use crate::common::{assert_script_error, blake160, generate_sighash_all};
use crate::core::{Pickaxer, Resource, Verifier};
use ckb_types::prelude::{Builder, Entity, Pack};
use k256::ecdsa::signature::SignerMut;

static BINARY_CCC_LOCK_SOL: &[u8] = include_bytes!("../../build/release/ccc-sol-lock");

fn message_wrap(msg: &str) -> String {
    // Only 32-bytes hex representation of the hash is allowed.
    assert_eq!(msg.len(), 64);
    // Text used to signify that a signed message follows and to prevent inadvertently signing a transaction.
    const CKB_PREFIX: &str = "Signing a CKB transaction: 0x";
    const CKB_SUFFIX: &str = "\n\nIMPORTANT: Please verify the integrity and authenticity of connected Solana wallet before signing this message\n";
    [CKB_PREFIX, msg, CKB_SUFFIX].join("")
}

fn message_sign(msg: &str, prikey: &mut ed25519_dalek::SigningKey) -> [u8; 64] {
    let msg = message_wrap(msg);
    prikey.sign(msg.as_bytes()).to_bytes()
}

fn default_tx(dl: &mut Resource, px: &mut Pickaxer) -> ckb_types::core::TransactionView {
    let tx_builder = ckb_types::core::TransactionBuilder::default();
    // Create prior knowledge
    let prikey_byte: [u8; 32] =
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let mut prikey = ed25519_dalek::SigningKey::from_bytes(&prikey_byte);
    let pubkey = prikey.verifying_key();
    let pubkey_byte = pubkey.to_bytes();
    let pubkey_hash = blake160(&pubkey_byte);
    // Create cell meta
    let cell_meta_ccc_lock_sol = px.insert_cell_data(dl, BINARY_CCC_LOCK_SOL);
    let cell_meta_i =
        px.insert_cell_fund(dl, px.create_script_by_type(&cell_meta_ccc_lock_sol, &pubkey_hash), None, &[]);
    // Create cell dep
    let tx_builder = tx_builder.cell_dep(px.create_cell_dep(&cell_meta_ccc_lock_sol));
    // Create input
    let tx_builder = tx_builder.input(px.create_cell_input(&cell_meta_i));
    // Create output
    let tx_builder =
        tx_builder.output(px.create_cell_output(px.create_script_by_type(&cell_meta_ccc_lock_sol, &pubkey_hash), None));
    // Create output data
    let tx_builder = tx_builder.output_data(ckb_types::packed::Bytes::default());
    // Create witness
    let tx_builder = tx_builder.set_witnesses(vec![ckb_types::packed::WitnessArgs::new_builder()
        .lock(Some(ckb_types::bytes::Bytes::from(vec![0u8; 96])).pack())
        .build()
        .as_bytes()
        .pack()]);
    let sighash_all = generate_sighash_all(&tx_builder.clone().build(), &dl, 0);
    let sighash_all_hex = hex::encode(&sighash_all);
    let mut sig = [0u8; 96];
    sig[..64].copy_from_slice(&message_sign(&sighash_all_hex, &mut prikey));
    sig[64..].copy_from_slice(&pubkey_byte);
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
    let cycles = verifier.verify(&tx_resolved, &dl).unwrap();
    assert!(cycles <= 2621440);
}

#[test]
fn test_failure_wrong_pubkey_hash_length() {
    let mut dl = Resource::default();
    let mut px = Pickaxer::default();
    let tx = default_tx(&mut dl, &mut px);

    let input_outpoint = tx.inputs().get_unchecked(0).previous_output();
    let input_meta = dl.cell.get_mut(&input_outpoint).unwrap();
    let input_cell_output = &input_meta.cell_output;
    let input_cell_output_script = input_cell_output.lock();
    let input_cell_output_script_args = input_cell_output_script.args().as_bytes();
    let input_cell_output_script =
        input_cell_output_script.as_builder().args(input_cell_output_script_args[..19].pack()).build();
    let input_cell_output = input_cell_output.clone().as_builder().lock(input_cell_output_script).build();
    input_meta.cell_output = input_cell_output;

    let tx_resolved =
        ckb_types::core::cell::resolve_transaction(tx, &mut std::collections::HashSet::new(), &dl, &dl).unwrap();
    let verifier = Verifier::default();
    assert_script_error(verifier.verify(&tx_resolved, &dl).unwrap_err(), 32);
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
    let input_cell_output_script = input_cell_output_script.as_builder().args(vec![0u8; 20].pack()).build();
    let input_cell_output = input_cell_output.clone().as_builder().lock(input_cell_output_script).build();
    input_meta.cell_output = input_cell_output;

    let tx_resolved =
        ckb_types::core::cell::resolve_transaction(tx, &mut std::collections::HashSet::new(), &dl, &dl).unwrap();
    let verifier = Verifier::default();
    assert_script_error(verifier.verify(&tx_resolved, &dl).unwrap_err(), 32);
}

#[test]
fn test_failure_wrong_signature_length() {
    let mut dl = Resource::default();
    let mut px = Pickaxer::default();
    let tx = default_tx(&mut dl, &mut px);

    let wa = ckb_types::packed::WitnessArgs::new_unchecked(tx.witnesses().get_unchecked(0).raw_data());
    let mut wa_lock = wa.lock().to_opt().unwrap().raw_data().to_vec();
    wa_lock.pop();
    let wa = wa.as_builder().lock(Some(ckb_types::bytes::Bytes::from(wa_lock)).pack()).build();
    let tx = tx.as_advanced_builder().set_witnesses(vec![wa.as_bytes().pack()]).build();

    let tx_resolved =
        ckb_types::core::cell::resolve_transaction(tx, &mut std::collections::HashSet::new(), &dl, &dl).unwrap();
    let verifier = Verifier::default();
    assert_script_error(verifier.verify(&tx_resolved, &dl).unwrap_err(), 33);
}

#[test]
fn test_failure_wrong_signature() {
    let mut dl = Resource::default();
    let mut px = Pickaxer::default();
    let tx = default_tx(&mut dl, &mut px);

    let wa = ckb_types::packed::WitnessArgs::new_unchecked(tx.witnesses().get_unchecked(0).raw_data());
    let mut wa_lock = wa.lock().to_opt().unwrap().raw_data().to_vec();
    wa_lock[..64].copy_from_slice(&[0u8; 64]);
    let wa = wa.as_builder().lock(Some(ckb_types::bytes::Bytes::from(wa_lock)).pack()).build();
    let tx = tx.as_advanced_builder().set_witnesses(vec![wa.as_bytes().pack()]).build();

    let tx_resolved =
        ckb_types::core::cell::resolve_transaction(tx, &mut std::collections::HashSet::new(), &dl, &dl).unwrap();
    let verifier = Verifier::default();
    assert_script_error(verifier.verify(&tx_resolved, &dl).unwrap_err(), 34);
}

#[test]
fn test_success_e2e() {
    let mut dl = Resource::default();
    let mut px = Pickaxer::default();
    let tx = default_tx(&mut dl, &mut px);

    // 1. Install Phantom
    // 2. Import account with private key AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFMtav2rXn79au8yvzCadhc0mUe1LiFtYafJBrt8KW6KQ==
    // 3. Open F12
    // 4. Run msg = new TextEncoder().encode('Signing a CKB transaction: 0xa5505c5d5261287569fdd26f4061ba7b3ec9bf1ef1baf
    //        6a43426ec115d625d37\n\nIMPORTANT: Please verify the integrity and authenticity of connected Solana wallet
    //        before signing this message\n');
    // 5. Run sig = await phantom.solana.signMessage(msg, 'utf8');
    // 6. Run sig.signature.toString('hex')

    let wa = ckb_types::packed::WitnessArgs::new_unchecked(tx.witnesses().get_unchecked(0).raw_data());
    let mut wa_lock = wa.lock().to_opt().unwrap().raw_data().to_vec();
    wa_lock[..64].copy_from_slice(
        &hex::decode("be179ec911d03817a14b871d5efc3b162651f644c252e16e1e97c1848ccc53784f5205d8aa2ce79774f877330e857cf78375dbdd377dfffb31405329a16dd101").unwrap()
    );
    let wa = wa.as_builder().lock(Some(ckb_types::bytes::Bytes::from(wa_lock)).pack()).build();
    let tx = tx.as_advanced_builder().set_witnesses(vec![wa.as_bytes().pack()]).build();

    let tx_resolved =
        ckb_types::core::cell::resolve_transaction(tx, &mut std::collections::HashSet::new(), &dl, &dl).unwrap();
    let verifier = Verifier::default();
    verifier.verify(&tx_resolved, &dl).unwrap();
}

#[test]
fn test_check_size() {
    assert!(BINARY_CCC_LOCK_SOL.len() <= 100 * 1024);
}
