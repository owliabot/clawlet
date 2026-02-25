//! Calldata validation for `send_raw` — only allows whitelisted UniswapV3 SwapRouter functions
//! targeting known router contract addresses.
//!
//! Uses alloy's `sol!` macro for ABI-level decoding rather than raw selector matching.

use alloy::primitives::{address, Address, Bytes};
use alloy::sol;
use alloy::sol_types::SolInterface;
use clawlet_core::chain::SupportedChainId;

/// Canonical UniswapV3 SwapRouter address, shared across all supported chains:
/// `0xE592427A0AEce92De3Edee1F18E0157C05861564`
const CANONICAL_SWAP_ROUTER: Address = address!("E592427A0AEce92De3Edee1F18E0157C05861564");

// UniswapV3 SwapRouter interface — only the 4 allowed swap functions.
sol! {
    /// UniswapV3 SwapRouter swap functions.
    interface ISwapRouter {
        struct ExactInputSingleParams {
            address tokenIn;
            address tokenOut;
            uint24 fee;
            address recipient;
            uint256 deadline;
            uint256 amountIn;
            uint256 amountOutMinimum;
            uint160 sqrtPriceLimitX96;
        }

        struct ExactInputParams {
            bytes path;
            address recipient;
            uint256 deadline;
            uint256 amountIn;
            uint256 amountOutMinimum;
        }

        struct ExactOutputSingleParams {
            address tokenIn;
            address tokenOut;
            uint24 fee;
            address recipient;
            uint256 deadline;
            uint256 amountOut;
            uint256 amountInMaximum;
            uint160 sqrtPriceLimitX96;
        }

        struct ExactOutputParams {
            bytes path;
            address recipient;
            uint256 deadline;
            uint256 amountOut;
            uint256 amountInMaximum;
        }

        function exactInputSingle(ExactInputSingleParams calldata params) external payable returns (uint256 amountOut);
        function exactInput(ExactInputParams calldata params) external payable returns (uint256 amountOut);
        function exactOutputSingle(ExactOutputSingleParams calldata params) external payable returns (uint256 amountIn);
        function exactOutput(ExactOutputParams calldata params) external payable returns (uint256 amountIn);
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
    /// The function selector is not one of the 4 allowed swap functions.
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

    // Try to ABI-decode as one of the 4 ISwapRouter functions.
    match ISwapRouter::ISwapRouterCalls::abi_decode(data) {
        Ok(call) => {
            let name = match call {
                ISwapRouter::ISwapRouterCalls::exactInputSingle(_) => "exactInputSingle",
                ISwapRouter::ISwapRouterCalls::exactInput(_) => "exactInput",
                ISwapRouter::ISwapRouterCalls::exactOutputSingle(_) => "exactOutputSingle",
                ISwapRouter::ISwapRouterCalls::exactOutput(_) => "exactOutput",
            };
            SwapValidation::Allowed(name.to_string())
        }
        Err(decode_err) => {
            // Check if the selector matches but args are malformed
            let selector: [u8; 4] = [data[0], data[1], data[2], data[3]];
            let known_selectors = [
                ([0x41, 0x4b, 0xf3, 0x89], "exactInputSingle"),
                ([0xc0, 0x4b, 0x8d, 0x59], "exactInput"),
                ([0xdb, 0x3e, 0x21, 0x98], "exactOutputSingle"),
                ([0xf2, 0x8c, 0x04, 0x98], "exactOutput"),
            ];

            for (sel, name) in &known_selectors {
                if selector == *sel {
                    return SwapValidation::MalformedArgs {
                        name: name.to_string(),
                        reason: decode_err.to_string(),
                    };
                }
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
                path: Bytes::from(vec![0u8; 43]), // token+fee+token
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
        let data = encode_exact_input_single();
        assert!(matches!(
            validate_swap_calldata(&Some(data)),
            SwapValidation::Allowed(name) if name == "exactInputSingle"
        ));
    }

    #[test]
    fn exact_input_valid() {
        let data = encode_exact_input();
        assert!(matches!(
            validate_swap_calldata(&Some(data)),
            SwapValidation::Allowed(name) if name == "exactInput"
        ));
    }

    #[test]
    fn exact_output_single_valid() {
        let data = encode_exact_output_single();
        assert!(matches!(
            validate_swap_calldata(&Some(data)),
            SwapValidation::Allowed(name) if name == "exactOutputSingle"
        ));
    }

    #[test]
    fn exact_output_valid() {
        let data = encode_exact_output();
        assert!(matches!(
            validate_swap_calldata(&Some(data)),
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
        // exactInputSingle selector with garbage args
        let data = Bytes::from(vec![0x41, 0x4b, 0xf3, 0x89, 0xff, 0xff]);
        assert!(matches!(
            validate_swap_calldata(&Some(data)),
            SwapValidation::MalformedArgs { name, .. } if name == "exactInputSingle"
        ));
    }

    #[test]
    fn selector_only_is_malformed() {
        let data = Bytes::from(vec![0xc0, 0x4b, 0x8d, 0x59]);
        assert!(matches!(
            validate_swap_calldata(&Some(data)),
            SwapValidation::MalformedArgs { name, .. } if name == "exactInput"
        ));
    }
}
