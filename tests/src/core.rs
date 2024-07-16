use ckb_types::prelude::{Builder, Entity, Pack};

#[derive(Clone, Default)]
pub struct Resource {
    pub cell:
        std::collections::HashMap<ckb_types::packed::OutPoint, ckb_types::core::cell::CellMeta>,
}

impl ckb_traits::CellDataProvider for Resource {
    fn get_cell_data(
        &self,
        out_point: &ckb_types::packed::OutPoint,
    ) -> Option<ckb_types::bytes::Bytes> {
        self.cell
            .get(out_point)
            .and_then(|cell_meta| cell_meta.mem_cell_data.clone())
    }

    fn get_cell_data_hash(
        &self,
        out_point: &ckb_types::packed::OutPoint,
    ) -> Option<ckb_types::packed::Byte32> {
        self.cell
            .get(out_point)
            .and_then(|cell_meta| cell_meta.mem_cell_data_hash.clone())
    }
}

impl ckb_traits::HeaderProvider for Resource {
    fn get_header(&self, _: &ckb_types::packed::Byte32) -> Option<ckb_types::core::HeaderView> {
        unimplemented!()
    }
}

impl ckb_traits::ExtensionProvider for Resource {
    fn get_block_extension(
        &self,
        _: &ckb_types::packed::Byte32,
    ) -> Option<ckb_types::packed::Bytes> {
        unimplemented!()
    }
}

impl ckb_types::core::cell::CellProvider for Resource {
    fn cell(
        &self,
        out_point: &ckb_types::packed::OutPoint,
        eager_load: bool,
    ) -> ckb_types::core::cell::CellStatus {
        let _ = eager_load;
        if let Some(data) = self.cell.get(out_point).cloned() {
            ckb_types::core::cell::CellStatus::Live(data)
        } else {
            ckb_types::core::cell::CellStatus::Unknown
        }
    }
}

impl ckb_types::core::cell::HeaderChecker for Resource {
    fn check_valid(
        &self,
        _: &ckb_types::packed::Byte32,
    ) -> Result<(), ckb_types::core::error::OutPointError> {
        Ok(())
    }
}

#[derive(Clone, Default)]
pub struct Verifier {}

impl Verifier {
    pub fn verify_prior(
        &self,
        tx_resolved: &ckb_types::core::cell::ResolvedTransaction,
        _: &Resource,
    ) {
        let a = tx_resolved.transaction.outputs().item_count();
        let b = tx_resolved.transaction.outputs_data().item_count();
        assert_eq!(a, b);
    }

    pub fn verify(
        &self,
        tx_resolved: &ckb_types::core::cell::ResolvedTransaction,
        dl: &Resource,
    ) -> Result<ckb_types::core::Cycle, ckb_error::Error> {
        self.verify_prior(&tx_resolved, &dl);
        let hardfork = ckb_types::core::hardfork::HardForks {
            ckb2021: ckb_types::core::hardfork::CKB2021::new_dev_default(),
            ckb2023: ckb_types::core::hardfork::CKB2023::new_dev_default(),
        };
        let consensus = ckb_chain_spec::consensus::ConsensusBuilder::default()
            .hardfork_switch(hardfork)
            .build();
        let mut verifier = ckb_script::TransactionScriptsVerifier::new(
            std::sync::Arc::new(tx_resolved.clone()),
            dl.clone(),
            std::sync::Arc::new(consensus),
            std::sync::Arc::new(ckb_script::TxVerifyEnv::new_submit(
                &ckb_types::core::HeaderView::new_advanced_builder()
                    .epoch(ckb_types::core::EpochNumberWithFraction::new(0, 0, 1).pack())
                    .build(),
            )),
        );
        verifier.set_debug_printer(|script: &ckb_types::packed::Byte32, msg: &str| {
            let str = format!("Script({})", hex::encode(&script.as_slice()[..4]));
            println!("{}: {}", str, msg);
        });
        let result = verifier.verify(u64::MAX);
        if result.is_ok() {
            let cycles = (*result.as_ref().unwrap() as f64) / 1024.0 / 1024.0;
            println_log(&format!("cycles is {:.1} M ", cycles));
        }
        result
    }
}

#[derive(Clone, Default)]
pub struct Pickaxer {
    outpoint_hash: ckb_types::packed::Byte32,
    outpoint_i: u32,
}

impl Pickaxer {
    pub fn insert_cell_data(
        &mut self,
        dl: &mut Resource,
        data: &[u8],
    ) -> ckb_types::core::cell::CellMeta {
        let cell_out_point =
            ckb_types::packed::OutPoint::new(self.outpoint_hash.clone(), self.outpoint_i);
        let cell_output = ckb_types::packed::CellOutput::new_builder()
            .capacity(ckb_types::core::Capacity::bytes(0).unwrap().pack())
            .build();
        let cell_data = ckb_types::bytes::Bytes::copy_from_slice(data);
        let cell_meta =
            ckb_types::core::cell::CellMetaBuilder::from_cell_output(cell_output, cell_data)
                .out_point(cell_out_point.clone())
                .build();
        dl.cell.insert(cell_out_point.clone(), cell_meta.clone());
        self.outpoint_i += 1;
        cell_meta
    }

    pub fn insert_cell_fund(
        &mut self,
        dl: &mut Resource,
        lock: ckb_types::packed::Script,
        kype: Option<ckb_types::packed::Script>,
        data: &[u8],
    ) -> ckb_types::core::cell::CellMeta {
        let cell_out_point =
            ckb_types::packed::OutPoint::new(self.outpoint_hash.clone(), self.outpoint_i);
        let cell_output = ckb_types::packed::CellOutput::new_builder()
            .capacity(ckb_types::core::Capacity::bytes(0).unwrap().pack())
            .lock(lock)
            .type_(
                ckb_types::packed::ScriptOpt::new_builder()
                    .set(kype)
                    .build(),
            )
            .build();
        let cell_data = ckb_types::bytes::Bytes::copy_from_slice(data);
        let cell_meta =
            ckb_types::core::cell::CellMetaBuilder::from_cell_output(cell_output, cell_data)
                .out_point(cell_out_point.clone())
                .build();
        dl.cell.insert(cell_out_point.clone(), cell_meta.clone());
        self.outpoint_i += 1;
        cell_meta
    }

    pub fn create_cell_dep(
        &self,
        cell_meta: &ckb_types::core::cell::CellMeta,
    ) -> ckb_types::packed::CellDep {
        ckb_types::packed::CellDep::new_builder()
            .out_point(cell_meta.out_point.clone())
            .dep_type(ckb_types::core::DepType::Code.into())
            .build()
    }

    pub fn create_cell_input(
        &self,
        cell_meta: &ckb_types::core::cell::CellMeta,
    ) -> ckb_types::packed::CellInput {
        ckb_types::packed::CellInput::new(cell_meta.out_point.clone(), 0)
    }

    pub fn create_cell_output(
        &self,
        lock: ckb_types::packed::Script,
        kype: Option<ckb_types::packed::Script>,
    ) -> ckb_types::packed::CellOutput {
        ckb_types::packed::CellOutput::new_builder()
            .capacity(ckb_types::core::Capacity::bytes(0).unwrap().pack())
            .lock(lock)
            .type_(
                ckb_types::packed::ScriptOpt::new_builder()
                    .set(kype)
                    .build(),
            )
            .build()
    }

    pub fn create_script(
        &self,
        cell_meta: &ckb_types::core::cell::CellMeta,
        args: &[u8],
    ) -> ckb_types::packed::Script {
        ckb_types::packed::Script::new_builder()
            .args(args.pack())
            .code_hash(cell_meta.mem_cell_data_hash.clone().unwrap())
            .hash_type(ckb_types::core::ScriptHashType::Data1.into())
            .build()
    }
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
