use crate::common::{assert_script_error, generate_sighash_all, println_hex};
use crate::core::{Pickaxer, Resource, Verifier};
use ckb_types::prelude::{Builder, Entity, Pack};
use sha3::Digest;

static BINARY_CCC_LOCK_ETH: &[u8] = include_bytes!("../../build/release/ccc-eth-lock");

fn keccak(msg: &[u8]) -> [u8; 32] {
    let mut hasher = sha3::Keccak256::new();
    hasher.update(msg);
    hasher.finalize().into()
}

fn keccak160(msg: &[u8]) -> [u8; 20] {
    let mut output = [0u8; 20];
    output.copy_from_slice(&keccak(msg)[12..]);
    output
}

fn message_hash(msg: &str) -> [u8; 32] {
    // Only 32-bytes hex representation of the hash is allowed.
    assert_eq!(msg.len(), 64);
    // Text used to signify that a signed message follows and to prevent inadvertently signing a transaction.
    const CKB_PREFIX: &str = "Signing a CKB transaction: 0x";
    const CKB_SUFFIX: &str = "\n\nIMPORTANT: Please verify the integrity and authenticity of connected Ethereum wallet before signing this message\n";
    const ETH_PREFIX: &str = "Ethereum Signed Message:\n";
    let mut data: Vec<u8> = Vec::new();
    assert_eq!(ETH_PREFIX.len(), 25);
    data.push(25);
    data.extend(ETH_PREFIX.as_bytes());
    data.extend(format!("{}", (CKB_PREFIX.len() + msg.len() + CKB_SUFFIX.len()) as u8).as_bytes());
    data.extend(CKB_PREFIX.as_bytes());
    data.extend(msg.as_bytes());
    data.extend(CKB_SUFFIX.as_bytes());
    keccak(&data)
}

fn message_sign(msg: &str, prikey: &k256::ecdsa::SigningKey) -> [u8; 65] {
    let m = message_hash(msg);
    let sigrec = prikey.sign_prehash_recoverable(&m).unwrap();
    if sigrec.1.to_byte() > 2 {
        return message_sign(msg, prikey);
    }
    let mut r = [0u8; 65];
    r[..64].copy_from_slice(&sigrec.0.normalize_s().unwrap_or(sigrec.0).to_bytes());
    r[64] = 27 + sigrec.1.to_byte();
    r
}

fn default_tx(dl: &mut Resource, px: &mut Pickaxer) -> ckb_types::core::TransactionView {
    let tx_builder = ckb_types::core::TransactionBuilder::default();
    // Create prior knowledge
    let prikey_byte: [u8; 32] =
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let prikey = k256::ecdsa::SigningKey::from_slice(&prikey_byte).unwrap();
    let pubkey = prikey.verifying_key();
    let pubkey_hash = keccak160(&pubkey.to_encoded_point(false).to_bytes()[1..]);
    println_hex("pubkey_hash_expect", &pubkey_hash);
    // Create cell meta
    let cell_meta_ccc_lock_eth = px.insert_cell_data(dl, BINARY_CCC_LOCK_ETH);
    let cell_meta_i =
        px.insert_cell_fund(dl, px.create_script_by_type(&cell_meta_ccc_lock_eth, &pubkey_hash), None, &[]);
    // Create cell dep
    let tx_builder = tx_builder.cell_dep(px.create_cell_dep(&cell_meta_ccc_lock_eth));
    // Create input
    let tx_builder = tx_builder.input(px.create_cell_input(&cell_meta_i));
    // Create output
    let tx_builder =
        tx_builder.output(px.create_cell_output(px.create_script_by_type(&cell_meta_ccc_lock_eth, &pubkey_hash), None));
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
    let cycles = verifier.verify(&tx_resolved, &dl).unwrap();
    assert!(cycles <= 4718592);
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
    wa_lock[0x20..0x40].copy_from_slice(&vec![0u8; 32]);
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
    wa_lock[64] = 4;
    let wa = wa.as_builder().lock(Some(ckb_types::bytes::Bytes::from(wa_lock)).pack()).build();
    let tx = tx.as_advanced_builder().set_witnesses(vec![wa.as_bytes().pack()]).build();

    let tx_resolved =
        ckb_types::core::cell::resolve_transaction(tx, &mut std::collections::HashSet::new(), &dl, &dl).unwrap();
    let verifier = Verifier::default();
    assert_script_error(verifier.verify(&tx_resolved, &dl).unwrap_err(), 35);
}

#[test]
fn test_success_sig_use_high_s() {
    let mut dl = Resource::default();
    let mut px = Pickaxer::default();
    let tx = default_tx(&mut dl, &mut px);

    let wa = ckb_types::packed::WitnessArgs::new_unchecked(tx.witnesses().get_unchecked(0).raw_data());
    let mut wa_lock = wa.lock().to_opt().unwrap().raw_data().to_vec();
    let l_s = k256::NonZeroScalar::try_from(&wa_lock[32..64]).unwrap();
    let h_s = -l_s;
    wa_lock[32..64].copy_from_slice(&h_s.to_bytes().as_slice());
    wa_lock[64] = 55 - wa_lock[64];
    let wa = wa.as_builder().lock(Some(ckb_types::bytes::Bytes::from(wa_lock)).pack()).build();
    let tx = tx.as_advanced_builder().set_witnesses(vec![wa.as_bytes().pack()]).build();

    let tx_resolved =
        ckb_types::core::cell::resolve_transaction(tx, &mut std::collections::HashSet::new(), &dl, &dl).unwrap();
    let verifier = Verifier::default();
    verifier.verify(&tx_resolved, &dl).unwrap();
}

#[test]
fn test_success_e2e() {
    let mut dl = Resource::default();
    let mut px = Pickaxer::default();
    let tx = default_tx(&mut dl, &mut px);

    // 1. Install Metamask
    // 2. Import account with private key 0x0000000000000000000000000000000000000000000000000000000000000001
    // 3. Open F12
    // 4. Run await ethereum.enable()
    // 5. Run await ethereum.send('personal_sign', ['5369676e696e67206120434b42207472616e73616374696f6e3a203078363665306
    //        4383366303062633332336363316665316530383336653038616234363838653036646537353164366534383133633537383738326
    //        66565363032370a0a494d504f5254414e543a20506c65617365207665726966792074686520696e7465677269747920616e6420617
    //        57468656e746963697479206f6620636f6e6e656374656420457468657265756d2077616c6c6574206265666f7265207369676e696
    //        e672074686973206d6573736167650a', '0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf'])
    let wa = ckb_types::packed::WitnessArgs::new_unchecked(tx.witnesses().get_unchecked(0).raw_data());
    let mut wa_lock = wa.lock().to_opt().unwrap().raw_data().to_vec();
    wa_lock.copy_from_slice(&hex::decode("2291abe57fc51d83a90b3002c3b1994393a56a3cbdfd54a0fd1ece34971607b020eb1c750dbd1f159c631681e7cf1d6e97a0929299b039d6e93a9d7170b6440d1b").unwrap());
    let wa = wa.as_builder().lock(Some(ckb_types::bytes::Bytes::from(wa_lock)).pack()).build();
    let tx = tx.as_advanced_builder().set_witnesses(vec![wa.as_bytes().pack()]).build();

    let tx_resolved =
        ckb_types::core::cell::resolve_transaction(tx, &mut std::collections::HashSet::new(), &dl, &dl).unwrap();
    let verifier = Verifier::default();
    verifier.verify(&tx_resolved, &dl).unwrap();
}

#[test]
fn test_check_size() {
    assert!(BINARY_CCC_LOCK_ETH.len() <= 150 * 1024);
}
