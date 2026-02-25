//! Calldata validation for `send_raw` — only allows whitelisted UniswapV3 SwapRouter functions
//! targeting known router contract addresses.
//!
//! The allowed functions are defined by the ABI JSON file at `abi/ISwapRouter.json`.

use alloy::primitives::{address, Address, Bytes};
use alloy::sol;
use alloy::sol_types::SolInterface;
use clawlet_core::chain::SupportedChainId;

/// Canonical UniswapV3 SwapRouter address, shared across all supported chains:
/// `0xE592427A0AEce92De3Edee1F18E0157C05861564`
const CANONICAL_SWAP_ROUTER: Address = address!("E592427A0AEce92De3Edee1F18E0157C05861564");

// Load UniswapV3 SwapRouter interface from ABI JSON.
sol!(
    #[sol(abi)]
    ISwapRouter,
    "abi/ISwapRouter.json"
);

/// Map a successfully decoded call to its function name.
fn call_name(call: &ISwapRouter::ISwapRouterCalls) -> &'static str {
    match call {
        ISwapRouter::ISwapRouterCalls::exactInputSingle(_) => "exactInputSingle",
        ISwapRouter::ISwapRouterCalls::exactInput(_) => "exactInput",
        ISwapRouter::ISwapRouterCalls::exactOutputSingle(_) => "exactOutputSingle",
        ISwapRouter::ISwapRouterCalls::exactOutput(_) => "exactOutput",
    }
}

/// Try to identify a known function name from a 4-byte selector.
///
/// Selectors derived from the canonical Solidity signatures:
/// - exactInputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160)): 0x414bf389
/// - exactInput((bytes,address,uint256,uint256,uint256)): 0xc04b8d59
/// - exactOutputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160)): 0xdb3e2198
/// - exactOutput((bytes,address,uint256,uint256,uint256)): 0xf28c0498
fn selector_name(selector: [u8; 4]) -> Option<&'static str> {
    match selector {
        [0x41, 0x4b, 0xf3, 0x89] => Some("exactInputSingle"),
        [0xc0, 0x4b, 0x8d, 0x59] => Some("exactInput"),
        [0xdb, 0x3e, 0x21, 0x98] => Some("exactOutputSingle"),
        [0xf2, 0x8c, 0x04, 0x98] => Some("exactOutput"),
        _ => None,
    }
}

/// Returns `true` if `to` is the known UniswapV3 SwapRouter for the given chain.
pub fn is_allowed_router(to: Address, chain: SupportedChainId) -> bool {
    let _ = chain; // chain already validated via enum
    to == CANONICAL_SWAP_ROUTER
}

/// Result of validating raw transaction calldata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SwapValidation {
    /// The calldata is a valid, ABI-decodable UniswapV3 swap call.
    Allowed(String),
    /// The calldata is missing or too short to contain a function selector.
    NoSelector,
    /// The function selector is not one of the allowed swap functions.
    Denied { selector: [u8; 4] },
    /// The function selector matches but ABI decoding failed (malformed args).
    MalformedArgs { name: String, reason: String },
}

/// Validate that the calldata corresponds to an allowed UniswapV3 SwapRouter function
/// and can be ABI-decoded successfully.
pub fn validate_swap_calldata(data: &Option<Bytes>) -> SwapValidation {
    let data = match data {
        Some(d) if d.len() >= 4 => d,
        _ => return SwapValidation::NoSelector,
    };

    // Try full ABI decode against the ISwapRouter interface.
    match ISwapRouter::ISwapRouterCalls::abi_decode(data) {
        Ok(call) => SwapValidation::Allowed(call_name(&call).to_string()),
        Err(decode_err) => {
            let selector: [u8; 4] = [data[0], data[1], data[2], data[3]];

            // Known selector but bad args → malformed
            if let Some(name) = selector_name(selector) {
                return SwapValidation::MalformedArgs {
                    name: name.to_string(),
                    reason: decode_err.to_string(),
                };
            }

            SwapValidation::Denied { selector }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{Uint, U160, U256};
    use alloy::sol_types::SolCall;

    // ---- Router address tests ----

    #[test]
    fn canonical_router_allowed_on_all_chains() {
        for chain in SupportedChainId::ALL {
            assert!(
                is_allowed_router(CANONICAL_SWAP_ROUTER, chain),
                "canonical router should be allowed on {chain}"
            );
        }
    }

    #[test]
    fn random_address_denied() {
        let random = address!("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
        assert!(!is_allowed_router(random, SupportedChainId::Ethereum));
        assert!(!is_allowed_router(random, SupportedChainId::Bnb));
    }

    #[test]
    fn unknown_chain_rejected_at_type_level() {
        assert!(SupportedChainId::try_from(999u64).is_err());
        assert!(SupportedChainId::try_from(43114u64).is_err());
    }

    // ---- ABI decode tests ----

    fn encode_exact_input_single() -> Bytes {
        let call = ISwapRouter::exactInputSingleCall {
            params: ISwapRouter::ExactInputSingleParams {
                tokenIn: Address::ZERO,
                tokenOut: address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
                fee: Uint::from(3000u32),
                recipient: Address::ZERO,
                deadline: U256::from(9999999999u64),
                amountIn: U256::from(1_000_000_000_000_000_000u64),
                amountOutMinimum: U256::from(1u64),
                sqrtPriceLimitX96: U160::ZERO,
            },
        };
        Bytes::from(call.abi_encode())
    }

    fn encode_exact_input() -> Bytes {
        let call = ISwapRouter::exactInputCall {
            params: ISwapRouter::ExactInputParams {
                path: Bytes::from(vec![0u8; 43]),
                recipient: Address::ZERO,
                deadline: U256::from(9999999999u64),
                amountIn: U256::from(1_000_000_000_000_000_000u64),
                amountOutMinimum: U256::from(1u64),
            },
        };
        Bytes::from(call.abi_encode())
    }

    fn encode_exact_output_single() -> Bytes {
        let call = ISwapRouter::exactOutputSingleCall {
            params: ISwapRouter::ExactOutputSingleParams {
                tokenIn: Address::ZERO,
                tokenOut: address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
                fee: Uint::from(3000u32),
                recipient: Address::ZERO,
                deadline: U256::from(9999999999u64),
                amountOut: U256::from(1000000u64),
                amountInMaximum: U256::MAX,
                sqrtPriceLimitX96: U160::ZERO,
            },
        };
        Bytes::from(call.abi_encode())
    }

    fn encode_exact_output() -> Bytes {
        let call = ISwapRouter::exactOutputCall {
            params: ISwapRouter::ExactOutputParams {
                path: Bytes::from(vec![0u8; 43]),
                recipient: Address::ZERO,
                deadline: U256::from(9999999999u64),
                amountOut: U256::from(1000000u64),
                amountInMaximum: U256::MAX,
            },
        };
        Bytes::from(call.abi_encode())
    }

    #[test]
    fn exact_input_single_valid() {
        assert!(matches!(
            validate_swap_calldata(&Some(encode_exact_input_single())),
            SwapValidation::Allowed(name) if name == "exactInputSingle"
        ));
    }

    #[test]
    fn exact_input_valid() {
        assert!(matches!(
            validate_swap_calldata(&Some(encode_exact_input())),
            SwapValidation::Allowed(name) if name == "exactInput"
        ));
    }

    #[test]
    fn exact_output_single_valid() {
        assert!(matches!(
            validate_swap_calldata(&Some(encode_exact_output_single())),
            SwapValidation::Allowed(name) if name == "exactOutputSingle"
        ));
    }

    #[test]
    fn exact_output_valid() {
        assert!(matches!(
            validate_swap_calldata(&Some(encode_exact_output())),
            SwapValidation::Allowed(name) if name == "exactOutput"
        ));
    }

    #[test]
    fn unknown_selector_denied() {
        let data = Bytes::from(vec![0xde, 0xad, 0xbe, 0xef, 0x00, 0x00]);
        assert!(matches!(
            validate_swap_calldata(&Some(data)),
            SwapValidation::Denied { selector } if selector == [0xde, 0xad, 0xbe, 0xef]
        ));
    }

    #[test]
    fn empty_data_no_selector() {
        assert_eq!(validate_swap_calldata(&None), SwapValidation::NoSelector);
        assert_eq!(
            validate_swap_calldata(&Some(Bytes::new())),
            SwapValidation::NoSelector
        );
    }

    #[test]
    fn short_data_no_selector() {
        let data = Bytes::from(vec![0x41, 0x4b, 0xf3]);
        assert_eq!(
            validate_swap_calldata(&Some(data)),
            SwapValidation::NoSelector
        );
    }

    #[test]
    fn correct_selector_but_malformed_args() {
        // exactInputSingle selector (0x414bf389) with garbage args
        let mut data = vec![0x41, 0x4b, 0xf3, 0x89, 0xff, 0xff];
        assert!(matches!(
            validate_swap_calldata(&Some(Bytes::from(data))),
            SwapValidation::MalformedArgs { name, .. } if name == "exactInputSingle"
        ));
    }

    #[test]
    fn selector_only_is_malformed() {
        // exactInput selector (0xc04b8d59) with no args
        let data = vec![0xc0, 0x4b, 0x8d, 0x59];
        assert!(matches!(
            validate_swap_calldata(&Some(Bytes::from(data))),
            SwapValidation::MalformedArgs { name, .. } if name == "exactInput"
        ));
    }
}
