//! AIS (Agent Interaction Spec) definitions and parser.
//!
//! AIS specs describe DeFi operations as declarative YAML.

use serde::Deserialize;
use std::collections::HashMap;
use thiserror::Error;

/// Errors arising from AIS spec parsing and loading.
#[derive(Debug, Error)]
pub enum AisError {
    #[error("failed to parse AIS YAML: {0}")]
    Parse(#[from] serde_yaml::Error),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Top-level AIS spec.
#[derive(Debug, Clone, Deserialize)]
pub struct AisSpec {
    /// AIS spec version.
    pub spec_version: String,
    /// Unique name for the skill.
    pub name: String,
    /// Protocol name.
    pub protocol: String,
    /// Chain ID for execution.
    pub chain_id: u64,
    /// Optional human-readable description.
    pub description: Option<String>,
    /// Action sequence.
    pub actions: Vec<AisAction>,
    /// Parameter schema.
    #[serde(default)]
    pub params: HashMap<String, AisParam>,
}

impl AisSpec {
    /// Parse an AIS spec from a YAML string.
    pub fn from_yaml(yaml: &str) -> Result<Self, AisError> {
        Ok(serde_yaml::from_str(yaml)?)
    }

    /// Load an AIS spec from a YAML file.
    pub fn from_file(path: &std::path::Path) -> Result<Self, AisError> {
        let contents = std::fs::read_to_string(path)?;
        Self::from_yaml(&contents)
    }
}

/// Action types supported by AIS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AisActionType {
    /// An EVM contract call.
    EvmCall,
    /// A composite action that references other actions by id.
    Composite,
}

/// A single AIS action.
#[derive(Debug, Clone, Deserialize)]
pub struct AisAction {
    /// Action identifier.
    pub id: String,
    /// Action type.
    #[serde(rename = "type")]
    pub action_type: AisActionType,
    /// Target contract address (template-supported).
    pub contract: Option<String>,
    /// Function signature, e.g. `approve(address,uint256)`.
    pub function: Option<String>,
    /// ABI arguments for the call.
    pub args: Option<Vec<AisArg>>,
    /// Optional description.
    pub description: Option<String>,
    /// Whether the action requires token approval before execution.
    #[serde(default)]
    pub requires_approval: bool,
    /// Optional approval hints for smart-approve handling.
    pub approval: Option<AisApproval>,
    /// Composite action steps (action IDs).
    pub steps: Option<Vec<String>>,
}

/// Approval hints for smart-approve handling.
#[derive(Debug, Clone, Deserialize)]
pub struct AisApproval {
    /// Token contract address.
    pub token: String,
    /// Spender address.
    pub spender: String,
    /// Approval amount.
    pub amount: String,
}

/// Parameter metadata.
#[derive(Debug, Clone, Deserialize)]
pub struct AisParam {
    /// Solidity type (e.g. address, uint256).
    #[serde(rename = "type")]
    pub param_type: String,
    /// Optional description.
    pub description: Option<String>,
    /// Optional default value (as string).
    pub default: Option<String>,
}

/// ABI argument value or tuple.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum AisArg {
    /// A simple value (string / template).
    Value(String),
    /// A tuple value with fields.
    Tuple(AisTupleArg),
}

/// Tuple argument representation.
#[derive(Debug, Clone, Deserialize)]
pub struct AisTupleArg {
    /// Must be `tuple`.
    #[serde(rename = "type")]
    pub type_name: String,
    /// Tuple fields.
    pub fields: Vec<AisArg>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_uniswap_example() {
        let yaml = r#"
spec_version: "0.1"
name: "uniswap_v3_swap"
protocol: "Uniswap V3"
chain_id: 1
description: "Swap tokens via Uniswap V3 SwapRouter"
actions:
  - id: "approve_token"
    type: evm_call
    contract: "{{token_in}}"
    function: "approve(address,uint256)"
    args:
      - "{{router_address}}"
      - "{{amount_in}}"
    description: "Approve router to spend input token"
  - id: "swap"
    type: evm_call
    contract: "{{router_address}}"
    function: "exactInputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160))"
    args:
      - type: tuple
        fields:
          - "{{token_in}}"
          - "{{token_out}}"
          - "{{fee_tier}}"
          - "{{recipient}}"
          - "{{deadline}}"
          - "{{amount_in}}"
          - "{{min_amount_out}}"
          - "0"
    description: "Execute swap"
params:
  token_in: { type: address, description: "Input token address" }
  token_out: { type: address, description: "Output token address" }
  amount_in: { type: uint256, description: "Amount of input token" }
  min_amount_out: { type: uint256, description: "Minimum output amount (slippage protection)" }
  fee_tier: { type: uint24, default: "3000", description: "Pool fee tier" }
  router_address: { type: address, default: "0xE592427A0AEce92De3Edee1F18E0157C05861564" }
  recipient: { type: address, description: "Recipient of output tokens" }
  deadline: { type: uint256, description: "Transaction deadline timestamp" }
"#;

        let spec = AisSpec::from_yaml(yaml).expect("parse AIS spec");
        assert_eq!(spec.name, "uniswap_v3_swap");
        assert_eq!(spec.chain_id, 1);
        assert_eq!(spec.actions.len(), 2);

        let approve = &spec.actions[0];
        assert_eq!(approve.action_type, AisActionType::EvmCall);
        assert_eq!(approve.contract.as_deref(), Some("{{token_in}}"));

        let swap = &spec.actions[1];
        assert_eq!(swap.action_type, AisActionType::EvmCall);
        let args = swap.args.as_ref().unwrap();
        match &args[0] {
            AisArg::Tuple(t) => {
                assert_eq!(t.type_name, "tuple");
                assert_eq!(t.fields.len(), 8);
            }
            _ => panic!("expected tuple arg"),
        }

        let fee = spec.params.get("fee_tier").unwrap();
        assert_eq!(fee.default.as_deref(), Some("3000"));
    }
}
