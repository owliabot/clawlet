//! Calldata validation for `send_raw` — only allows whitelisted Uniswap router functions
//! targeting known router contract addresses.
//!
//! The allowed functions are defined by the ABI JSON files at:
//! - `abi/ISwapRouter.json` (Uniswap V3 SwapRouter02 / IV3SwapRouter)
//! - `abi/IUniswapV2Router.json` (UniswapV2-like Router02 interfaces)

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

// Load UniswapV2-like Router02 interface from ABI JSON.
sol!(
    #[sol(abi)]
    IUniswapV2Router,
    "abi/IUniswapV2Router.json"
);

/// SwapRouter02 addresses per chain (from Uniswap official deployments).
///
/// Source: <https://docs.uniswap.org/contracts/v3/reference/deployments>
fn swap_router_v3_address(chain: SupportedChainId) -> Address {
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

/// UniswapV2-like Router02 addresses per chain.
fn swap_router_v2_address(chain: SupportedChainId) -> Address {
    match chain {
        SupportedChainId::Ethereum => address!("7a250d5630B4cF539739dF2C5dAcb4c659F2488D"),
        SupportedChainId::Bnb => address!("10ED43C718714eb63d5aA57B78B54704E256024E"),
        SupportedChainId::Polygon => address!("a5E0829CaCEd8fFDD4De3c43696c57F7D7A678ff"),
        SupportedChainId::Arbitrum | SupportedChainId::Base => {
            address!("4752ba5DBc23f44D87826276BF6Fd6b1C372aD24")
        }
        SupportedChainId::Optimism => address!("4A7b5Da61326A6379179b40d00F57E5bbDC962c2"),
    }
}

/// Returns `true` if `to` is a known Uniswap router (V2/V3) for the given chain.
pub fn is_allowed_router(to: Address, chain: SupportedChainId) -> bool {
    to == swap_router_v3_address(chain) || to == swap_router_v2_address(chain)
}

/// Try to identify a known function name from a 4-byte selector.
///
/// SwapRouter02 (IV3SwapRouter) selectors:
/// - exactInputSingle:  0x04e45aaf
/// - exactInput:        0xb858183f
/// - exactOutputSingle: 0x5023b4df
/// - exactOutput:       0x09b81346
fn selector_name_v3(selector: [u8; 4]) -> Option<&'static str> {
    match selector {
        [0x04, 0xe4, 0x5a, 0xaf] => Some("exactInputSingle"),
        [0xb8, 0x58, 0x18, 0x3f] => Some("exactInput"),
        [0x50, 0x23, 0xb4, 0xdf] => Some("exactOutputSingle"),
        [0x09, 0xb8, 0x13, 0x46] => Some("exactOutput"),
        _ => None,
    }
}

fn selector_name_v2(selector: [u8; 4]) -> Option<&'static str> {
    match selector {
        [0x38, 0xed, 0x17, 0x39] => Some("swapExactTokensForTokens"),
        [0x7f, 0xf3, 0x6a, 0xb5] => Some("swapExactETHForTokens"),
        [0x18, 0xcb, 0xaf, 0xe5] => Some("swapExactTokensForETH"),
        _ => None,
    }
}

fn selector_name(selector: [u8; 4]) -> Option<&'static str> {
    selector_name_v3(selector).or_else(|| selector_name_v2(selector))
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
    /// The calldata is a valid, ABI-decodable Uniswap swap call.
    Allowed(SwapParams),
    /// The calldata is missing or too short to contain a function selector.
    NoSelector,
    /// The function selector is not one of the allowed swap functions.
    Denied { selector: [u8; 4] },
    /// The function selector matches but ABI decoding failed (malformed args).
    MalformedArgs { name: String, reason: String },
}

/// A decoded hop in a Uniswap V3 multi-hop path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathHop {
    pub token_in: Address,
    pub fee: u32,
    pub token_out: Address,
}

/// Decode a Uniswap V3 path into a list of hops.
///
/// Path encoding: `token(20) | fee(3) | token(20) [| fee(3) | token(20) ]*`
/// Returns `None` if the path is malformed (wrong length or too short).
pub fn decode_v3_path(path: &Bytes) -> Option<Vec<PathHop>> {
    // Minimum: 20 + 3 + 20 = 43 bytes for one hop
    if path.len() < 43 {
        return None;
    }
    // Structure check: (len - 20) must be divisible by 23
    if !((path.len() - 20).is_multiple_of(23)) {
        return None;
    }

    let num_hops = (path.len() - 20) / 23;
    let mut hops = Vec::with_capacity(num_hops);
    let mut offset = 0;

    for _ in 0..num_hops {
        let token_in = Address::from_slice(&path[offset..offset + 20]);
        offset += 20;
        let fee = ((path[offset] as u32) << 16)
            | ((path[offset + 1] as u32) << 8)
            | (path[offset + 2] as u32);
        offset += 3;
        let token_out = Address::from_slice(&path[offset..offset + 20]);
        // Don't advance offset past token_out — it's the next hop's token_in

        hops.push(PathHop {
            token_in,
            fee,
            token_out,
        });
    }

    Some(hops)
}

/// Extract tokenIn from a V3 path for `exactInput` (first token).
fn first_token_from_path(path: &Bytes) -> Option<Address> {
    decode_v3_path(path).map(|hops| hops[0].token_in)
}

/// Extract tokenIn from a V3 path for `exactOutput` (last token in reversed path).
fn last_token_from_path(path: &Bytes) -> Option<Address> {
    decode_v3_path(path).map(|hops| hops.last().unwrap().token_out)
}

/// Validate that the calldata corresponds to an allowed Uniswap router function
/// and can be ABI-decoded successfully. Returns parsed swap parameters on success.
pub fn validate_swap_calldata(data: &Option<Bytes>) -> SwapValidation {
    let data = match data {
        Some(d) if d.len() >= 4 => d,
        _ => return SwapValidation::NoSelector,
    };
    let selector: [u8; 4] = [data[0], data[1], data[2], data[3]];

    match ISwapRouter::ISwapRouterCalls::abi_decode(data) {
        Ok(call) => {
            let params = match &call {
                ISwapRouter::ISwapRouterCalls::exactInputSingle(c) => SwapParams {
                    function: "exactInputSingle".into(),
                    token_in: c.params.tokenIn,
                    amount_in: c.params.amountIn,
                },
                ISwapRouter::ISwapRouterCalls::exactInput(c) => {
                    let token_in = match first_token_from_path(&c.params.path) {
                        Some(addr) => addr,
                        None => {
                            return SwapValidation::MalformedArgs {
                                name: "exactInput".into(),
                                reason: format!(
                                    "invalid V3 path: length {} (expected 20 + 23*n, n >= 1)",
                                    c.params.path.len()
                                ),
                            };
                        }
                    };
                    SwapParams {
                        function: "exactInput".into(),
                        token_in,
                        amount_in: c.params.amountIn,
                    }
                }
                ISwapRouter::ISwapRouterCalls::exactOutputSingle(c) => SwapParams {
                    function: "exactOutputSingle".into(),
                    token_in: c.params.tokenIn,
                    amount_in: c.params.amountInMaximum,
                },
                ISwapRouter::ISwapRouterCalls::exactOutput(c) => {
                    let token_in = match last_token_from_path(&c.params.path) {
                        Some(addr) => addr,
                        None => {
                            return SwapValidation::MalformedArgs {
                                name: "exactOutput".into(),
                                reason: format!(
                                    "invalid V3 path: length {} (expected 20 + 23*n, n >= 1)",
                                    c.params.path.len()
                                ),
                            };
                        }
                    };
                    SwapParams {
                        function: "exactOutput".into(),
                        token_in,
                        amount_in: c.params.amountInMaximum,
                    }
                }
            };
            SwapValidation::Allowed(params)
        }
        Err(v3_decode_err) => {
            if let Some(name) = selector_name_v3(selector) {
                return SwapValidation::MalformedArgs {
                    name: name.to_string(),
                    reason: v3_decode_err.to_string(),
                };
            }

            match IUniswapV2Router::IUniswapV2RouterCalls::abi_decode(data) {
                Ok(call) => {
                    let params = match &call {
                        IUniswapV2Router::IUniswapV2RouterCalls::swapExactTokensForTokens(c) => {
                            let token_in = match c.path.first() {
                                Some(addr) => *addr,
                                None => {
                                    return SwapValidation::MalformedArgs {
                                        name: "swapExactTokensForTokens".into(),
                                        reason: "path must contain at least one token".into(),
                                    };
                                }
                            };
                            SwapParams {
                                function: "swapExactTokensForTokens".into(),
                                token_in,
                                amount_in: c.amountIn,
                            }
                        }
                        IUniswapV2Router::IUniswapV2RouterCalls::swapExactETHForTokens(c) => {
                            if c.path.is_empty() {
                                return SwapValidation::MalformedArgs {
                                    name: "swapExactETHForTokens".into(),
                                    reason: "path must contain at least one token".into(),
                                };
                            }
                            SwapParams {
                                function: "swapExactETHForTokens".into(),
                                token_in: Address::ZERO,
                                amount_in: U256::ZERO,
                            }
                        }
                        IUniswapV2Router::IUniswapV2RouterCalls::swapExactTokensForETH(c) => {
                            let token_in = match c.path.first() {
                                Some(addr) => *addr,
                                None => {
                                    return SwapValidation::MalformedArgs {
                                        name: "swapExactTokensForETH".into(),
                                        reason: "path must contain at least one token".into(),
                                    };
                                }
                            };
                            SwapParams {
                                function: "swapExactTokensForETH".into(),
                                token_in,
                                amount_in: c.amountIn,
                            }
                        }
                        // All other V2 Router functions (addLiquidity, removeLiquidity, etc.)
                        // are valid ABI but not whitelisted for send_raw.
                        _ => {
                            return SwapValidation::Denied { selector };
                        }
                    };
                    SwapValidation::Allowed(params)
                }
                Err(v2_decode_err) => {
                    if let Some(name) = selector_name(selector) {
                        return SwapValidation::MalformedArgs {
                            name: name.to_string(),
                            reason: v2_decode_err.to_string(),
                        };
                    }

                    SwapValidation::Denied { selector }
                }
            }
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
        // Ethereum
        assert!(is_allowed_router(
            address!("68b3465833fb72A70ecDF485E0e4C7bD8665Fc45"),
            SupportedChainId::Ethereum
        ));
        assert!(is_allowed_router(
            address!("7a250d5630B4cF539739dF2C5dAcb4c659F2488D"),
            SupportedChainId::Ethereum
        ));

        // Optimism
        assert!(is_allowed_router(
            address!("68b3465833fb72A70ecDF485E0e4C7bD8665Fc45"),
            SupportedChainId::Optimism
        ));
        assert!(is_allowed_router(
            address!("4A7b5Da61326A6379179b40d00F57E5bbDC962c2"),
            SupportedChainId::Optimism
        ));

        // Polygon
        assert!(is_allowed_router(
            address!("68b3465833fb72A70ecDF485E0e4C7bD8665Fc45"),
            SupportedChainId::Polygon
        ));
        assert!(is_allowed_router(
            address!("a5E0829CaCEd8fFDD4De3c43696c57F7D7A678ff"),
            SupportedChainId::Polygon
        ));

        // Arbitrum
        assert!(is_allowed_router(
            address!("68b3465833fb72A70ecDF485E0e4C7bD8665Fc45"),
            SupportedChainId::Arbitrum
        ));
        assert!(is_allowed_router(
            address!("4752ba5DBc23f44D87826276BF6Fd6b1C372aD24"),
            SupportedChainId::Arbitrum
        ));

        // Base
        assert!(is_allowed_router(
            address!("2626664c2603336E57B271c5C0b26F421741e481"),
            SupportedChainId::Base
        ));
        assert!(is_allowed_router(
            address!("4752ba5DBc23f44D87826276BF6Fd6b1C372aD24"),
            SupportedChainId::Base
        ));

        // BNB
        assert!(is_allowed_router(
            address!("B971eF87ede563556b2ED4b1C0b0019111Dd85d2"),
            SupportedChainId::Bnb
        ));
        assert!(is_allowed_router(
            address!("10ED43C718714eb63d5aA57B78B54704E256024E"),
            SupportedChainId::Bnb
        ));
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

    // ---- V2 decode tests ----

    fn encode_swap_exact_tokens_for_tokens() -> Bytes {
        let call = IUniswapV2Router::swapExactTokensForTokensCall {
            amountIn: U256::from(10_000u64),
            amountOutMin: U256::from(9_500u64),
            path: vec![WETH, USDC],
            to: Address::ZERO,
            deadline: U256::from(1_700_000_000u64),
        };
        Bytes::from(call.abi_encode())
    }

    fn encode_swap_exact_eth_for_tokens() -> Bytes {
        let call = IUniswapV2Router::swapExactETHForTokensCall {
            amountOutMin: U256::from(9_500u64),
            path: vec![WETH, USDC],
            to: Address::ZERO,
            deadline: U256::from(1_700_000_000u64),
        };
        Bytes::from(call.abi_encode())
    }

    fn encode_swap_exact_tokens_for_eth() -> Bytes {
        let call = IUniswapV2Router::swapExactTokensForETHCall {
            amountIn: U256::from(10_000u64),
            amountOutMin: U256::from(9_500u64),
            path: vec![USDC, WETH],
            to: Address::ZERO,
            deadline: U256::from(1_700_000_000u64),
        };
        Bytes::from(call.abi_encode())
    }

    #[test]
    fn swap_exact_tokens_for_tokens_valid() {
        match validate_swap_calldata(&Some(encode_swap_exact_tokens_for_tokens())) {
            SwapValidation::Allowed(p) => {
                assert_eq!(p.function, "swapExactTokensForTokens");
                assert_eq!(p.token_in, WETH);
                assert_eq!(p.amount_in, U256::from(10_000u64));
            }
            other => panic!("expected Allowed, got {:?}", other),
        }
    }

    #[test]
    fn swap_exact_eth_for_tokens_valid() {
        match validate_swap_calldata(&Some(encode_swap_exact_eth_for_tokens())) {
            SwapValidation::Allowed(p) => {
                assert_eq!(p.function, "swapExactETHForTokens");
                assert_eq!(p.token_in, Address::ZERO);
                assert_eq!(p.amount_in, U256::ZERO);
            }
            other => panic!("expected Allowed, got {:?}", other),
        }
    }

    #[test]
    fn swap_exact_tokens_for_eth_valid() {
        match validate_swap_calldata(&Some(encode_swap_exact_tokens_for_eth())) {
            SwapValidation::Allowed(p) => {
                assert_eq!(p.function, "swapExactTokensForETH");
                assert_eq!(p.token_in, USDC);
                assert_eq!(p.amount_in, U256::from(10_000u64));
            }
            other => panic!("expected Allowed, got {:?}", other),
        }
    }

    #[test]
    fn v2_selector_only_is_malformed() {
        // swapExactTokensForTokens selector (0x38ed1739) with no args
        let data = Bytes::from(vec![0x38, 0xed, 0x17, 0x39]);
        assert!(matches!(
            validate_swap_calldata(&Some(data)),
            SwapValidation::MalformedArgs { name, .. } if name == "swapExactTokensForTokens"
        ));
    }

    #[test]
    fn v2_eth_for_tokens_selector_only_is_malformed() {
        // swapExactETHForTokens selector (0x7ff36ab5) with no args
        let data = Bytes::from(vec![0x7f, 0xf3, 0x6a, 0xb5]);
        assert!(matches!(
            validate_swap_calldata(&Some(data)),
            SwapValidation::MalformedArgs { name, .. } if name == "swapExactETHForTokens"
        ));
    }

    #[test]
    fn v2_tokens_for_eth_selector_only_is_malformed() {
        // swapExactTokensForETH selector (0x18cbafe5) with no args
        let data = Bytes::from(vec![0x18, 0xcb, 0xaf, 0xe5]);
        assert!(matches!(
            validate_swap_calldata(&Some(data)),
            SwapValidation::MalformedArgs { name, .. } if name == "swapExactTokensForETH"
        ));
    }

    #[test]
    fn v2_tokens_for_eth_empty_path_rejected() {
        let call = IUniswapV2Router::swapExactTokensForETHCall {
            amountIn: U256::from(1u64),
            amountOutMin: U256::from(1u64),
            path: Vec::new(),
            to: Address::ZERO,
            deadline: U256::from(1u64),
        };
        let data = Bytes::from(call.abi_encode());
        assert!(matches!(
            validate_swap_calldata(&Some(data)),
            SwapValidation::MalformedArgs { name, .. } if name == "swapExactTokensForETH"
        ));
    }

    #[test]
    fn v2_tokens_for_tokens_empty_path_rejected() {
        let call = IUniswapV2Router::swapExactTokensForTokensCall {
            amountIn: U256::from(1u64),
            amountOutMin: U256::from(1u64),
            path: Vec::new(),
            to: Address::ZERO,
            deadline: U256::from(1u64),
        };
        let data = Bytes::from(call.abi_encode());
        assert!(matches!(
            validate_swap_calldata(&Some(data)),
            SwapValidation::MalformedArgs { name, .. } if name == "swapExactTokensForTokens"
        ));
    }

    #[test]
    fn v2_eth_for_tokens_empty_path_rejected() {
        let call = IUniswapV2Router::swapExactETHForTokensCall {
            amountOutMin: U256::from(1u64),
            path: Vec::new(),
            to: Address::ZERO,
            deadline: U256::from(1u64),
        };
        let data = Bytes::from(call.abi_encode());
        assert!(matches!(
            validate_swap_calldata(&Some(data)),
            SwapValidation::MalformedArgs { name, .. } if name == "swapExactETHForTokens"
        ));
    }

    // ---- V3 path validation tests ----

    #[test]
    fn exact_input_with_short_path_rejected() {
        // path = 20 bytes (too short, needs at least 43)
        let call = ISwapRouter::exactInputCall {
            params: IV3SwapRouter::ExactInputParams {
                path: Bytes::from(vec![0xAA; 20]),
                recipient: Address::ZERO,
                amountIn: U256::from(1u64),
                amountOutMinimum: U256::from(1u64),
            },
        };
        let data = Bytes::from(call.abi_encode());
        assert!(matches!(
            validate_swap_calldata(&Some(data)),
            SwapValidation::MalformedArgs { name, .. } if name == "exactInput"
        ));
    }

    #[test]
    fn exact_output_with_invalid_path_length_rejected() {
        // path = 44 bytes (not 20 + 23*n)
        let call = ISwapRouter::exactOutputCall {
            params: IV3SwapRouter::ExactOutputParams {
                path: Bytes::from(vec![0xBB; 44]),
                recipient: Address::ZERO,
                amountOut: U256::from(1u64),
                amountInMaximum: U256::MAX,
            },
        };
        let data = Bytes::from(call.abi_encode());
        assert!(matches!(
            validate_swap_calldata(&Some(data)),
            SwapValidation::MalformedArgs { name, .. } if name == "exactOutput"
        ));
    }

    #[test]
    fn valid_two_hop_path_accepted() {
        // Two hops: WETH -> fee -> USDC -> fee -> DAI = 20+3+20+3+20 = 66 bytes
        let dai = address!("6B175474E89094C44Da98b954EedeAC495271d0F");
        let mut path = Vec::with_capacity(66);
        path.extend_from_slice(WETH.as_slice());
        path.extend_from_slice(&[0x00, 0x0B, 0xB8]); // fee 3000
        path.extend_from_slice(USDC.as_slice());
        path.extend_from_slice(&[0x00, 0x01, 0xF4]); // fee 500
        path.extend_from_slice(dai.as_slice());

        let call = ISwapRouter::exactInputCall {
            params: IV3SwapRouter::ExactInputParams {
                path: Bytes::from(path),
                recipient: Address::ZERO,
                amountIn: U256::from(1_000_000_000_000_000_000u64),
                amountOutMinimum: U256::from(1u64),
            },
        };
        let data = Bytes::from(call.abi_encode());
        match validate_swap_calldata(&Some(data)) {
            SwapValidation::Allowed(p) => {
                assert_eq!(p.function, "exactInput");
                assert_eq!(
                    p.token_in, WETH,
                    "first token in two-hop path should be WETH"
                );
            }
            other => panic!("expected Allowed, got {:?}", other),
        }
    }

    #[test]
    fn decode_v3_path_single_hop() {
        let path = make_path(WETH, 3000, USDC);
        let hops = decode_v3_path(&path).unwrap();
        assert_eq!(hops.len(), 1);
        assert_eq!(hops[0].token_in, WETH);
        assert_eq!(hops[0].fee, 3000);
        assert_eq!(hops[0].token_out, USDC);
    }

    #[test]
    fn decode_v3_path_two_hops() {
        let dai = address!("6B175474E89094C44Da98b954EedeAC495271d0F");
        let mut path = Vec::with_capacity(66);
        path.extend_from_slice(WETH.as_slice());
        path.extend_from_slice(&[0x00, 0x0B, 0xB8]); // fee 3000
        path.extend_from_slice(USDC.as_slice());
        path.extend_from_slice(&[0x00, 0x01, 0xF4]); // fee 500
        path.extend_from_slice(dai.as_slice());
        let path = Bytes::from(path);

        let hops = decode_v3_path(&path).unwrap();
        assert_eq!(hops.len(), 2);
        assert_eq!(hops[0].token_in, WETH);
        assert_eq!(hops[0].fee, 3000);
        assert_eq!(hops[0].token_out, USDC);
        assert_eq!(hops[1].token_in, USDC);
        assert_eq!(hops[1].fee, 500);
        assert_eq!(hops[1].token_out, dai);
    }

    #[test]
    fn decode_v3_path_invalid_lengths() {
        assert!(decode_v3_path(&Bytes::from(vec![0u8; 0])).is_none());
        assert!(decode_v3_path(&Bytes::from(vec![0u8; 20])).is_none());
        assert!(decode_v3_path(&Bytes::from(vec![0u8; 42])).is_none());
        assert!(decode_v3_path(&Bytes::from(vec![0u8; 44])).is_none());
        assert!(decode_v3_path(&Bytes::from(vec![0u8; 65])).is_none());
        // Valid lengths
        assert!(decode_v3_path(&Bytes::from(vec![0u8; 43])).is_some());
        assert!(decode_v3_path(&Bytes::from(vec![0u8; 66])).is_some());
        assert!(decode_v3_path(&Bytes::from(vec![0u8; 89])).is_some());
    }
}
