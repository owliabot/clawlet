//! Calldata validation for `send_raw` — only allows whitelisted UniswapV3 SwapRouter02 functions
//! targeting known router contract addresses.
//!
//! The allowed functions are defined by the ABI JSON file at `abi/ISwapRouter.json`
//! (IV3SwapRouter interface from swap-router-contracts).

use alloy::primitives::{address, Address, Bytes, U256};
use alloy::sol;
use alloy::sol_types::SolInterface;
use clawlet_core::chain::SupportedChainId;

// Load UniswapV3 SwapRouter02 (IV3SwapRouter) interface from ABI JSON.
sol!(
    #[sol(abi)]
    ISwapRouter,
    "abi/ISwapRouter.json"
);

/// SwapRouter02 addresses per chain (from Uniswap official deployments).
///
/// Source: <https://docs.uniswap.org/contracts/v3/reference/deployments>
fn swap_router02_address(chain: SupportedChainId) -> Address {
    match chain {
        // Ethereum, Optimism, Polygon, Arbitrum share the same address
        SupportedChainId::Ethereum
        | SupportedChainId::Optimism
        | SupportedChainId::Polygon
        | SupportedChainId::Arbitrum => {
            address!("68b3465833fb72A70ecDF485E0e4C7bD8665Fc45")
        }
        // Base has a different deployment
        SupportedChainId::Base => address!("2626664c2603336E57B271c5C0b26F421741e481"),
        // BNB Chain has its own deployment
        SupportedChainId::Bnb => address!("B971eF87ede563556b2ED4b1C0b0019111Dd85d2"),
    }
}

/// Returns `true` if `to` is the known UniswapV3 SwapRouter02 for the given chain.
pub fn is_allowed_router(to: Address, chain: SupportedChainId) -> bool {
    to == swap_router02_address(chain)
}

/// Try to identify a known function name from a 4-byte selector.
///
/// SwapRouter02 (IV3SwapRouter) selectors:
/// - exactInputSingle:  0x04e45aaf
/// - exactInput:        0xb858183f
/// - exactOutputSingle: 0x5023b4df
/// - exactOutput:       0x09b81346
fn selector_name(selector: [u8; 4]) -> Option<&'static str> {
    match selector {
        [0x04, 0xe4, 0x5a, 0xaf] => Some("exactInputSingle"),
        [0xb8, 0x58, 0x18, 0x3f] => Some("exactInput"),
        [0x50, 0x23, 0xb4, 0xdf] => Some("exactOutputSingle"),
        [0x09, 0xb8, 0x13, 0x46] => Some("exactOutput"),
        _ => None,
    }
}

/// Parsed swap parameters for policy checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwapParams {
    /// Function name (e.g. "exactInputSingle").
    pub function: String,
    /// The input token address.
    pub token_in: Address,
    /// The input amount (amountIn for exactInput*, amountInMaximum for exactOutput*).
    pub amount_in: U256,
}

/// Result of validating raw transaction calldata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SwapValidation {
    /// The calldata is a valid, ABI-decodable UniswapV3 swap call.
    Allowed(SwapParams),
    /// The calldata is missing or too short to contain a function selector.
    NoSelector,
    /// The function selector is not one of the allowed swap functions.
    Denied { selector: [u8; 4] },
    /// The function selector matches but ABI decoding failed (malformed args).
    MalformedArgs { name: String, reason: String },
}

/// Minimum valid V3 path length: one hop = token(20) + fee(3) + token(20) = 43 bytes.
const MIN_PATH_LEN: usize = 43;

/// Extract the first token address from a Uniswap V3 multi-hop path.
///
/// Path encoding: `tokenA (20 bytes) | fee (3 bytes) | tokenB (20 bytes) | ...`
/// Used for `exactInput` where the first token in the path is tokenIn.
fn first_token_from_path(path: &Bytes) -> Option<Address> {
    if path.len() < MIN_PATH_LEN {
        return None;
    }
    Some(Address::from_slice(&path[..20]))
}

/// Extract the last token address from a Uniswap V3 multi-hop path.
///
/// Used for `exactOutput` where the path is reversed: the **last** 20 bytes are tokenIn.
fn last_token_from_path(path: &Bytes) -> Option<Address> {
    if path.len() < MIN_PATH_LEN {
        return None;
    }
    Some(Address::from_slice(&path[path.len() - 20..]))
}

/// Validate that the calldata corresponds to an allowed UniswapV3 SwapRouter02 function
/// and can be ABI-decoded successfully. Returns parsed swap parameters on success.
pub fn validate_swap_calldata(data: &Option<Bytes>) -> SwapValidation {
    let data = match data {
        Some(d) if d.len() >= 4 => d,
        _ => return SwapValidation::NoSelector,
    };

    match ISwapRouter::ISwapRouterCalls::abi_decode(data) {
        Ok(call) => {
            let params = match &call {
                ISwapRouter::ISwapRouterCalls::exactInputSingle(c) => SwapParams {
                    function: "exactInputSingle".into(),
                    token_in: c.params.tokenIn,
                    amount_in: c.params.amountIn,
                },
                ISwapRouter::ISwapRouterCalls::exactInput(c) => SwapParams {
                    function: "exactInput".into(),
                    token_in: first_token_from_path(&c.params.path).unwrap_or(Address::ZERO),
                    amount_in: c.params.amountIn,
                },
                ISwapRouter::ISwapRouterCalls::exactOutputSingle(c) => SwapParams {
                    function: "exactOutputSingle".into(),
                    token_in: c.params.tokenIn,
                    amount_in: c.params.amountInMaximum,
                },
                ISwapRouter::ISwapRouterCalls::exactOutput(c) => SwapParams {
                    function: "exactOutput".into(),
                    // For exactOutput the path is reversed: last token is tokenIn
                    token_in: last_token_from_path(&c.params.path).unwrap_or(Address::ZERO),
                    amount_in: c.params.amountInMaximum,
                },
            };
            SwapValidation::Allowed(params)
        }
        Err(decode_err) => {
            let selector: [u8; 4] = [data[0], data[1], data[2], data[3]];

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
    fn correct_router_per_chain() {
        // Ethereum/Optimism/Polygon/Arbitrum share one address
        let common = address!("68b3465833fb72A70ecDF485E0e4C7bD8665Fc45");
        assert!(is_allowed_router(common, SupportedChainId::Ethereum));
        assert!(is_allowed_router(common, SupportedChainId::Optimism));
        assert!(is_allowed_router(common, SupportedChainId::Polygon));
        assert!(is_allowed_router(common, SupportedChainId::Arbitrum));

        // Base has a different address
        let base_router = address!("2626664c2603336E57B271c5C0b26F421741e481");
        assert!(is_allowed_router(base_router, SupportedChainId::Base));
        assert!(!is_allowed_router(common, SupportedChainId::Base));

        // BNB has its own address
        let bnb_router = address!("B971eF87ede563556b2ED4b1C0b0019111Dd85d2");
        assert!(is_allowed_router(bnb_router, SupportedChainId::Bnb));
        assert!(!is_allowed_router(common, SupportedChainId::Bnb));
    }

    #[test]
    fn wrong_router_denied() {
        let random = address!("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
        for chain in SupportedChainId::ALL {
            assert!(
                !is_allowed_router(random, chain),
                "random address should be denied on {chain}"
            );
        }
    }

    #[test]
    fn old_swap_router_v1_denied() {
        // The old SwapRouter (0xE592...) should NOT be allowed
        let v1_router = address!("E592427A0AEce92De3Edee1F18E0157C05861564");
        for chain in SupportedChainId::ALL {
            assert!(
                !is_allowed_router(v1_router, chain),
                "SwapRouter V1 should be denied on {chain}"
            );
        }
    }

    #[test]
    fn unknown_chain_rejected_at_type_level() {
        assert!(SupportedChainId::try_from(999u64).is_err());
    }

    // ---- ABI decode tests (SwapRouter02 / IV3SwapRouter — no deadline field) ----

    fn encode_exact_input_single() -> Bytes {
        let call = ISwapRouter::exactInputSingleCall {
            params: IV3SwapRouter::ExactInputSingleParams {
                tokenIn: Address::ZERO,
                tokenOut: address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
                fee: Uint::from(3000u32),
                recipient: Address::ZERO,
                amountIn: U256::from(1_000_000_000_000_000_000u64),
                amountOutMinimum: U256::from(1u64),
                sqrtPriceLimitX96: U160::ZERO,
            },
        };
        Bytes::from(call.abi_encode())
    }

    // Build a V3 path: tokenA(20) + fee(3) + tokenB(20) = 43 bytes
    fn make_path(token_a: Address, fee: u32, token_b: Address) -> Bytes {
        let mut path = Vec::with_capacity(43);
        path.extend_from_slice(token_a.as_slice());
        path.push((fee >> 16) as u8);
        path.push((fee >> 8) as u8);
        path.push(fee as u8);
        path.extend_from_slice(token_b.as_slice());
        Bytes::from(path)
    }

    const WETH: Address = address!("C02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2");
    const USDC: Address = address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");

    fn encode_exact_input() -> Bytes {
        let call = ISwapRouter::exactInputCall {
            params: IV3SwapRouter::ExactInputParams {
                path: make_path(WETH, 3000, USDC),
                recipient: Address::ZERO,
                amountIn: U256::from(1_000_000_000_000_000_000u64),
                amountOutMinimum: U256::from(1u64),
            },
        };
        Bytes::from(call.abi_encode())
    }

    fn encode_exact_output_single() -> Bytes {
        let call = ISwapRouter::exactOutputSingleCall {
            params: IV3SwapRouter::ExactOutputSingleParams {
                tokenIn: Address::ZERO,
                tokenOut: address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
                fee: Uint::from(3000u32),
                recipient: Address::ZERO,
                amountOut: U256::from(1000000u64),
                amountInMaximum: U256::MAX,
                sqrtPriceLimitX96: U160::ZERO,
            },
        };
        Bytes::from(call.abi_encode())
    }

    fn encode_exact_output() -> Bytes {
        // exactOutput path is REVERSED: tokenOut -> fee -> tokenIn
        // So path = USDC(tokenOut) + fee + WETH(tokenIn)
        // tokenIn (WETH) should be extracted from the LAST 20 bytes
        let call = ISwapRouter::exactOutputCall {
            params: IV3SwapRouter::ExactOutputParams {
                path: make_path(USDC, 3000, WETH),
                recipient: Address::ZERO,
                amountOut: U256::from(1000000u64),
                amountInMaximum: U256::MAX,
            },
        };
        Bytes::from(call.abi_encode())
    }

    #[test]
    fn exact_input_single_valid() {
        match validate_swap_calldata(&Some(encode_exact_input_single())) {
            SwapValidation::Allowed(p) => {
                assert_eq!(p.function, "exactInputSingle");
                assert_eq!(p.token_in, Address::ZERO);
                assert_eq!(p.amount_in, U256::from(1_000_000_000_000_000_000u64));
            }
            other => panic!("expected Allowed, got {:?}", other),
        }
    }

    #[test]
    fn exact_input_valid() {
        match validate_swap_calldata(&Some(encode_exact_input())) {
            SwapValidation::Allowed(p) => {
                assert_eq!(p.function, "exactInput");
                // tokenIn is the FIRST token in the path (WETH)
                assert_eq!(p.token_in, WETH);
                assert_eq!(p.amount_in, U256::from(1_000_000_000_000_000_000u64));
            }
            other => panic!("expected Allowed, got {:?}", other),
        }
    }

    #[test]
    fn exact_output_single_valid() {
        match validate_swap_calldata(&Some(encode_exact_output_single())) {
            SwapValidation::Allowed(p) => {
                assert_eq!(p.function, "exactOutputSingle");
                assert_eq!(p.token_in, Address::ZERO);
                // amount_in is amountInMaximum
                assert_eq!(p.amount_in, U256::MAX);
            }
            other => panic!("expected Allowed, got {:?}", other),
        }
    }

    #[test]
    fn exact_output_valid() {
        match validate_swap_calldata(&Some(encode_exact_output())) {
            SwapValidation::Allowed(p) => {
                assert_eq!(p.function, "exactOutput");
                // tokenIn is the LAST token in the reversed path (WETH)
                assert_eq!(
                    p.token_in, WETH,
                    "exactOutput should extract tokenIn from last 20 bytes of reversed path"
                );
                assert_eq!(p.amount_in, U256::MAX);
            }
            other => panic!("expected Allowed, got {:?}", other),
        }
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
    fn old_v1_selectors_denied() {
        // SwapRouter V1 exactInputSingle selector (0x414bf389) should be denied
        let mut v = vec![0x41, 0x4b, 0xf3, 0x89];
        v.extend(vec![0x00u8; 260]);
        let data = Bytes::from(v);
        assert!(matches!(
            validate_swap_calldata(&Some(data)),
            SwapValidation::Denied { .. }
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
        let data = Bytes::from(vec![0x04, 0xe4, 0x5a]);
        assert_eq!(
            validate_swap_calldata(&Some(data)),
            SwapValidation::NoSelector
        );
    }

    #[test]
    fn correct_selector_but_malformed_args() {
        // exactInputSingle selector (0x04e45aaf) with garbage
        let data = Bytes::from(vec![0x04, 0xe4, 0x5a, 0xaf, 0xff, 0xff]);
        assert!(matches!(
            validate_swap_calldata(&Some(data)),
            SwapValidation::MalformedArgs { name, .. } if name == "exactInputSingle"
        ));
    }

    #[test]
    fn selector_only_is_malformed() {
        // exactInput selector (0xb858183f) with no args
        let data = Bytes::from(vec![0xb8, 0x58, 0x18, 0x3f]);
        assert!(matches!(
            validate_swap_calldata(&Some(data)),
            SwapValidation::MalformedArgs { name, .. } if name == "exactInput"
        ));
    }
}
