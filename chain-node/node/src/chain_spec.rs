use sc_service::{ChainType, Properties};
use nulla_runtime::WASM_BINARY;

/// Specialized `ChainSpec`. This is a specialization of the general Substrate ChainSpec type.
pub type ChainSpec = sc_service::GenericChainSpec;

pub fn development_chain_spec() -> Result<ChainSpec, String> {
	let mut props = Properties::new();
	props.insert("tokenSymbol".into(), "NULLA".into());
	props.insert("tokenDecimals".into(), 12.into());
	props.insert("ss58Format".into(), 42.into());

	Ok(ChainSpec::builder(
		WASM_BINARY.ok_or_else(|| "Development wasm not available".to_string())?,
		None,
	)
	.with_name("NULLA Development")
	.with_id("dev")
	.with_chain_type(ChainType::Development)
	.with_genesis_config_preset_name(sp_genesis_builder::DEV_RUNTIME_PRESET)
	.with_properties(props)
	.build())
}

pub fn local_chain_spec() -> Result<ChainSpec, String> {
	let mut props = Properties::new();
	props.insert("tokenSymbol".into(), "NULLA".into());
	props.insert("tokenDecimals".into(), 12.into());
	props.insert("ss58Format".into(), 42.into());

	Ok(ChainSpec::builder(
		WASM_BINARY.ok_or_else(|| "Development wasm not available".to_string())?,
		None,
	)
	.with_name("NULLA Local Testnet")
	.with_id("local_testnet")
	.with_chain_type(ChainType::Local)
	.with_genesis_config_preset_name(sp_genesis_builder::LOCAL_TESTNET_RUNTIME_PRESET)
	.with_properties(props)
	.build())
}
