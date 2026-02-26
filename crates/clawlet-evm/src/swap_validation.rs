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
        SupportedChainId::Bnb => address!("4752ba5DBc23f44D87826276BF6Fd6b1C372aD24"),
        SupportedChainId::Polygon => address!("edf6066a2b290C185783862C7F4776A2C8077AD1"),
        SupportedChainId::Arbitrum | SupportedChainId::Base => {
            address!("4752ba5DBc23f44D87826276BF6Fd6b1C372aD24")
        }
        SupportedChainId::Optimism => address!("4A7b5Da61326A6379179b40d00F57E5bbDC962c2"),
    }
}

/// Canonical wrapped native token (WETH/WBNB/WMATIC) per chain.
///
/// Used to validate that ETH-path V2 swaps reference the correct wrapped token.
pub fn wrapped_native_address(chain: SupportedChainId) -> Address {
    match chain {
        SupportedChainId::Ethereum => address!("C02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"),
        SupportedChainId::Bnb => address!("bb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c"),
        SupportedChainId::Polygon => address!("0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270"),
        SupportedChainId::Arbitrum => address!("82aF49447D8a07e3bd95BD0d56f35241523fBab1"),
        SupportedChainId::Base => address!("4200000000000000000000000000000000000006"),
        SupportedChainId::Optimism => address!("4200000000000000000000000000000000000006"),
    }
}

/// Uniswap router version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouterVersion {
    V2,
    V3,
}

/// Returns the router version if `to` is a known Uniswap router for the given chain.
pub fn identify_router(to: Address, chain: SupportedChainId) -> Option<RouterVersion> {
    if to == swap_router_v3_address(chain) {
        Some(RouterVersion::V3)
    } else if to == swap_router_v2_address(chain) {
        Some(RouterVersion::V2)
    } else {
        None
    }
}

/// Returns `true` if `to` is the known WETH contract for the given chain.
///
/// Uses `wrapped_native_address` which provides WETH/WBNB/WMATIC addresses per chain.
pub fn is_allowed_weth(to: Address, chain: SupportedChainId) -> bool {
    to == wrapped_native_address(chain)
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

/// Result of validating WETH wrap/unwrap calldata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WethValidation {
    /// The calldata is a valid WETH deposit (wrap) operation.
    Wrap(U256),
    /// The calldata is a valid WETH withdraw (unwrap) operation.
    Unwrap(U256),
    /// The calldata doesn't match deposit or withdraw patterns.
    Invalid { reason: String },
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

/// Validate calldata against the identified router version.
///
/// Uses the router version (determined from the `to` address) to decode
/// calldata with the correct ABI, avoiding cross-version false matches.
/// For V2, `chain` is used to validate WETH endpoints in ETH-path swaps.
pub fn validate_swap_calldata(
    data: &Option<Bytes>,
    version: RouterVersion,
    chain: SupportedChainId,
) -> SwapValidation {
    let data = match data {
        Some(d) if d.len() >= 4 => d,
        _ => return SwapValidation::NoSelector,
    };
    let selector: [u8; 4] = [data[0], data[1], data[2], data[3]];

    match version {
        RouterVersion::V3 => validate_v3(data, selector),
        RouterVersion::V2 => validate_v2(data, selector, chain),
    }
}

fn validate_v3(data: &Bytes, selector: [u8; 4]) -> SwapValidation {
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
        Err(err) => {
            if let Some(name) = selector_name_v3(selector) {
                SwapValidation::MalformedArgs {
                    name: name.to_string(),
                    reason: err.to_string(),
                }
            } else {
                SwapValidation::Denied { selector }
            }
        }
    }
}

fn validate_v2(data: &Bytes, selector: [u8; 4], chain: SupportedChainId) -> SwapValidation {
    let weth = wrapped_native_address(chain);

    match IUniswapV2Router::IUniswapV2RouterCalls::abi_decode(data) {
        Ok(call) => {
            let params = match &call {
                IUniswapV2Router::IUniswapV2RouterCalls::swapExactTokensForTokens(c) => {
                    if c.path.len() < 2 {
                        return SwapValidation::MalformedArgs {
                            name: "swapExactTokensForTokens".into(),
                            reason: format!(
                                "path must contain at least 2 tokens, got {}",
                                c.path.len()
                            ),
                        };
                    }
                    SwapParams {
                        function: "swapExactTokensForTokens".into(),
                        token_in: c.path[0],
                        amount_in: c.amountIn,
                    }
                }
                IUniswapV2Router::IUniswapV2RouterCalls::swapExactETHForTokens(c) => {
                    if c.path.len() < 2 {
                        return SwapValidation::MalformedArgs {
                            name: "swapExactETHForTokens".into(),
                            reason: format!(
                                "path must contain at least 2 tokens, got {}",
                                c.path.len()
                            ),
                        };
                    }
                    if c.path[0] != weth {
                        return SwapValidation::MalformedArgs {
                            name: "swapExactETHForTokens".into(),
                            reason: format!(
                                "path[0] must be wrapped native token ({weth}), got {}",
                                c.path[0]
                            ),
                        };
                    }
                    SwapParams {
                        function: "swapExactETHForTokens".into(),
                        token_in: weth,
                        amount_in: U256::ZERO, // ETH sent as msg.value
                    }
                }
                IUniswapV2Router::IUniswapV2RouterCalls::swapExactTokensForETH(c) => {
                    if c.path.len() < 2 {
                        return SwapValidation::MalformedArgs {
                            name: "swapExactTokensForETH".into(),
                            reason: format!(
                                "path must contain at least 2 tokens, got {}",
                                c.path.len()
                            ),
                        };
                    }
                    if c.path[c.path.len() - 1] != weth {
                        return SwapValidation::MalformedArgs {
                            name: "swapExactTokensForETH".into(),
                            reason: format!(
                                "path[last] must be wrapped native token ({weth}), got {}",
                                c.path[c.path.len() - 1]
                            ),
                        };
                    }
                    SwapParams {
                        function: "swapExactTokensForETH".into(),
                        token_in: c.path[0],
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
        Err(err) => {
            if let Some(name) = selector_name_v2(selector) {
                SwapValidation::MalformedArgs {
                    name: name.to_string(),
                    reason: err.to_string(),
                }
            } else {
                SwapValidation::Denied { selector }
            }
        }
    }
}

/// Validate WETH wrap/unwrap calldata.
///
/// - **deposit()** (wrap): selector `0xd0e30db0`, no args (or empty), value > 0
/// - **withdraw(uint256)** (unwrap): selector `0x2e1a7d4d`, one uint256 arg
pub fn validate_weth_calldata(data: &Option<Bytes>, value: Option<U256>) -> WethValidation {
    const DEPOSIT_SELECTOR: [u8; 4] = [0xd0, 0xe3, 0x0d, 0xb0];
    const WITHDRAW_SELECTOR: [u8; 4] = [0x2e, 0x1a, 0x7d, 0x4d];

    let data = match data {
        Some(d) if d.len() >= 4 => d,
        Some(d) if d.is_empty() => {
            // Empty data + value > 0 → fallback deposit
            let amount = value.unwrap_or(U256::ZERO);
            if amount.is_zero() {
                return WethValidation::Invalid {
                    reason: "empty calldata with zero value is not a valid WETH operation".into(),
                };
            }
            return WethValidation::Wrap(amount);
        }
        None => {
            // None (no calldata) + value > 0 → fallback deposit
            let amount = value.unwrap_or(U256::ZERO);
            if amount.is_zero() {
                return WethValidation::Invalid {
                    reason: "no calldata with zero value is not a valid WETH operation".into(),
                };
            }
            return WethValidation::Wrap(amount);
        }
        _ => {
            return WethValidation::Invalid {
                reason: "calldata too short for WETH operation".into(),
            };
        }
    };

    let selector: [u8; 4] = [data[0], data[1], data[2], data[3]];

    if selector == DEPOSIT_SELECTOR {
        // deposit() — no args or just the selector
        if data.len() != 4 {
            return WethValidation::Invalid {
                reason: format!(
                    "deposit() expects 4-byte calldata (selector only), got {} bytes",
                    data.len()
                ),
            };
        }
        let amount = value.unwrap_or(U256::ZERO);
        if amount.is_zero() {
            return WethValidation::Invalid {
                reason: "deposit() requires value > 0".into(),
            };
        }
        return WethValidation::Wrap(amount);
    }

    if selector == WITHDRAW_SELECTOR {
        // withdraw(uint256 wad) — selector + 32 bytes
        if data.len() != 36 {
            return WethValidation::Invalid {
                reason: format!(
                    "withdraw(uint256) expects 36-byte calldata (4 + 32), got {} bytes",
                    data.len()
                ),
            };
        }
        // Decode the uint256 amount from bytes 4..36
        let amount = U256::from_be_slice(&data[4..36]);
        if amount.is_zero() {
            return WethValidation::Invalid {
                reason: "withdraw amount must be > 0".into(),
            };
        }
        return WethValidation::Unwrap(amount);
    }

    WethValidation::Invalid {
        reason: format!(
            "unknown WETH selector: 0x{:02x}{:02x}{:02x}{:02x}",
            selector[0], selector[1], selector[2], selector[3]
        ),
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
        // Ethereum V3
        assert_eq!(
            identify_router(
                address!("68b3465833fb72A70ecDF485E0e4C7bD8665Fc45"),
                SupportedChainId::Ethereum
            ),
            Some(RouterVersion::V3)
        );
        // Ethereum V2
        assert_eq!(
            identify_router(
                address!("7a250d5630B4cF539739dF2C5dAcb4c659F2488D"),
                SupportedChainId::Ethereum
            ),
            Some(RouterVersion::V2)
        );

        // Optimism V3
        assert_eq!(
            identify_router(
                address!("68b3465833fb72A70ecDF485E0e4C7bD8665Fc45"),
                SupportedChainId::Optimism
            ),
            Some(RouterVersion::V3)
        );
        // Optimism V2
        assert_eq!(
            identify_router(
                address!("4A7b5Da61326A6379179b40d00F57E5bbDC962c2"),
                SupportedChainId::Optimism
            ),
            Some(RouterVersion::V2)
        );

        // Polygon V3
        assert_eq!(
            identify_router(
                address!("68b3465833fb72A70ecDF485E0e4C7bD8665Fc45"),
                SupportedChainId::Polygon
            ),
            Some(RouterVersion::V3)
        );
        // Polygon V2
        assert_eq!(
            identify_router(
                address!("edf6066a2b290C185783862C7F4776A2C8077AD1"),
                SupportedChainId::Polygon
            ),
            Some(RouterVersion::V2)
        );

        // Arbitrum V3
        assert_eq!(
            identify_router(
                address!("68b3465833fb72A70ecDF485E0e4C7bD8665Fc45"),
                SupportedChainId::Arbitrum
            ),
            Some(RouterVersion::V3)
        );
        // Arbitrum V2
        assert_eq!(
            identify_router(
                address!("4752ba5DBc23f44D87826276BF6Fd6b1C372aD24"),
                SupportedChainId::Arbitrum
            ),
            Some(RouterVersion::V2)
        );

        // Base V3
        assert_eq!(
            identify_router(
                address!("2626664c2603336E57B271c5C0b26F421741e481"),
                SupportedChainId::Base
            ),
            Some(RouterVersion::V3)
        );
        // Base V2
        assert_eq!(
            identify_router(
                address!("4752ba5DBc23f44D87826276BF6Fd6b1C372aD24"),
                SupportedChainId::Base
            ),
            Some(RouterVersion::V2)
        );

        // BNB V3
        assert_eq!(
            identify_router(
                address!("B971eF87ede563556b2ED4b1C0b0019111Dd85d2"),
                SupportedChainId::Bnb
            ),
            Some(RouterVersion::V3)
        );
        // BNB V2
        assert_eq!(
            identify_router(
                address!("4752ba5DBc23f44D87826276BF6Fd6b1C372aD24"),
                SupportedChainId::Bnb
            ),
            Some(RouterVersion::V2)
        );
    }

    #[test]
    fn wrong_router_denied() {
        let random = address!("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
        for chain in SupportedChainId::ALL {
            assert!(
                identify_router(random, chain).is_none(),
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
                identify_router(v1_router, chain).is_none(),
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
        match validate_swap_calldata(
            &Some(encode_exact_input_single()),
            RouterVersion::V3,
            SupportedChainId::Ethereum,
        ) {
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
        match validate_swap_calldata(
            &Some(encode_exact_input()),
            RouterVersion::V3,
            SupportedChainId::Ethereum,
        ) {
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
        match validate_swap_calldata(
            &Some(encode_exact_output_single()),
            RouterVersion::V3,
            SupportedChainId::Ethereum,
        ) {
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
        match validate_swap_calldata(
            &Some(encode_exact_output()),
            RouterVersion::V3,
            SupportedChainId::Ethereum,
        ) {
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
            validate_swap_calldata(&Some(data), RouterVersion::V3, SupportedChainId::Ethereum),
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
            validate_swap_calldata(&Some(data), RouterVersion::V3, SupportedChainId::Ethereum),
            SwapValidation::Denied { .. }
        ));
    }

    #[test]
    fn empty_data_no_selector() {
        assert_eq!(
            validate_swap_calldata(&None, RouterVersion::V3, SupportedChainId::Ethereum),
            SwapValidation::NoSelector
        );
        assert_eq!(
            validate_swap_calldata(
                &Some(Bytes::new()),
                RouterVersion::V3,
                SupportedChainId::Ethereum
            ),
            SwapValidation::NoSelector
        );
    }

    #[test]
    fn short_data_no_selector() {
        let data = Bytes::from(vec![0x04, 0xe4, 0x5a]);
        assert_eq!(
            validate_swap_calldata(&Some(data), RouterVersion::V3, SupportedChainId::Ethereum),
            SwapValidation::NoSelector
        );
    }

    #[test]
    fn correct_selector_but_malformed_args() {
        // exactInputSingle selector (0x04e45aaf) with garbage
        let data = Bytes::from(vec![0x04, 0xe4, 0x5a, 0xaf, 0xff, 0xff]);
        assert!(matches!(
            validate_swap_calldata(&Some(data), RouterVersion::V3, SupportedChainId::Ethereum),
            SwapValidation::MalformedArgs { name, .. } if name == "exactInputSingle"
        ));
    }

    #[test]
    fn selector_only_is_malformed() {
        // exactInput selector (0xb858183f) with no args
        let data = Bytes::from(vec![0xb8, 0x58, 0x18, 0x3f]);
        assert!(matches!(
            validate_swap_calldata(&Some(data), RouterVersion::V3, SupportedChainId::Ethereum),
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
        match validate_swap_calldata(
            &Some(encode_swap_exact_tokens_for_tokens()),
            RouterVersion::V2,
            SupportedChainId::Ethereum,
        ) {
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
        match validate_swap_calldata(
            &Some(encode_swap_exact_eth_for_tokens()),
            RouterVersion::V2,
            SupportedChainId::Ethereum,
        ) {
            SwapValidation::Allowed(p) => {
                assert_eq!(p.function, "swapExactETHForTokens");
                assert_eq!(p.token_in, WETH); // path[0] is WETH
                assert_eq!(p.amount_in, U256::ZERO); // ETH sent as msg.value
            }
            other => panic!("expected Allowed, got {:?}", other),
        }
    }

    #[test]
    fn swap_exact_tokens_for_eth_valid() {
        match validate_swap_calldata(
            &Some(encode_swap_exact_tokens_for_eth()),
            RouterVersion::V2,
            SupportedChainId::Ethereum,
        ) {
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
            validate_swap_calldata(&Some(data), RouterVersion::V2, SupportedChainId::Ethereum),
            SwapValidation::MalformedArgs { name, .. } if name == "swapExactTokensForTokens"
        ));
    }

    #[test]
    fn v2_eth_for_tokens_selector_only_is_malformed() {
        // swapExactETHForTokens selector (0x7ff36ab5) with no args
        let data = Bytes::from(vec![0x7f, 0xf3, 0x6a, 0xb5]);
        assert!(matches!(
            validate_swap_calldata(&Some(data), RouterVersion::V2, SupportedChainId::Ethereum),
            SwapValidation::MalformedArgs { name, .. } if name == "swapExactETHForTokens"
        ));
    }

    #[test]
    fn v2_tokens_for_eth_selector_only_is_malformed() {
        // swapExactTokensForETH selector (0x18cbafe5) with no args
        let data = Bytes::from(vec![0x18, 0xcb, 0xaf, 0xe5]);
        assert!(matches!(
            validate_swap_calldata(&Some(data), RouterVersion::V2, SupportedChainId::Ethereum),
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
            validate_swap_calldata(&Some(data), RouterVersion::V2, SupportedChainId::Ethereum),
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
            validate_swap_calldata(&Some(data), RouterVersion::V2, SupportedChainId::Ethereum),
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
            validate_swap_calldata(&Some(data), RouterVersion::V2, SupportedChainId::Ethereum),
            SwapValidation::MalformedArgs { name, .. } if name == "swapExactETHForTokens"
        ));
    }

    #[test]
    fn v2_single_token_path_rejected() {
        // path with only 1 token should be rejected (V2 requires >= 2)
        let call = IUniswapV2Router::swapExactTokensForTokensCall {
            amountIn: U256::from(1u64),
            amountOutMin: U256::from(1u64),
            path: vec![WETH],
            to: Address::ZERO,
            deadline: U256::from(1u64),
        };
        let data = Bytes::from(call.abi_encode());
        assert!(matches!(
            validate_swap_calldata(&Some(data), RouterVersion::V2, SupportedChainId::Ethereum),
            SwapValidation::MalformedArgs { name, reason } if name == "swapExactTokensForTokens" && reason.contains("at least 2")
        ));

        let call = IUniswapV2Router::swapExactETHForTokensCall {
            amountOutMin: U256::from(1u64),
            path: vec![WETH],
            to: Address::ZERO,
            deadline: U256::from(1u64),
        };
        let data = Bytes::from(call.abi_encode());
        assert!(matches!(
            validate_swap_calldata(&Some(data), RouterVersion::V2, SupportedChainId::Ethereum),
            SwapValidation::MalformedArgs { name, reason } if name == "swapExactETHForTokens" && reason.contains("at least 2")
        ));

        let call = IUniswapV2Router::swapExactTokensForETHCall {
            amountIn: U256::from(1u64),
            amountOutMin: U256::from(1u64),
            path: vec![USDC],
            to: Address::ZERO,
            deadline: U256::from(1u64),
        };
        let data = Bytes::from(call.abi_encode());
        assert!(matches!(
            validate_swap_calldata(&Some(data), RouterVersion::V2, SupportedChainId::Ethereum),
            SwapValidation::MalformedArgs { name, reason } if name == "swapExactTokensForETH" && reason.contains("at least 2")
        ));
    }

    // ---- Cross-version mismatch tests ----

    #[test]
    fn v2_calldata_with_v3_version_denied() {
        // V2 swapExactTokensForTokens calldata validated as V3 → Denied
        let data = encode_swap_exact_tokens_for_tokens();
        assert!(matches!(
            validate_swap_calldata(&Some(data), RouterVersion::V3, SupportedChainId::Ethereum),
            SwapValidation::Denied { .. }
        ));
    }

    #[test]
    fn v3_calldata_with_v2_version_denied() {
        // V3 exactInputSingle calldata validated as V2 → Denied
        let data = encode_exact_input_single();
        assert!(matches!(
            validate_swap_calldata(&Some(data), RouterVersion::V2, SupportedChainId::Ethereum),
            SwapValidation::Denied { .. }
        ));
    }

    // ---- WETH endpoint validation tests ----

    #[test]
    fn v2_eth_for_tokens_wrong_weth_rejected() {
        // path[0] is not WETH → should be rejected
        let call = IUniswapV2Router::swapExactETHForTokensCall {
            amountOutMin: U256::from(9_500u64),
            path: vec![USDC, WETH], // wrong: path[0] should be WETH
            to: Address::ZERO,
            deadline: U256::from(1_700_000_000u64),
        };
        let data = Bytes::from(call.abi_encode());
        assert!(matches!(
            validate_swap_calldata(&Some(data), RouterVersion::V2, SupportedChainId::Ethereum),
            SwapValidation::MalformedArgs { name, reason }
                if name == "swapExactETHForTokens" && reason.contains("wrapped native token")
        ));
    }

    #[test]
    fn v2_tokens_for_eth_wrong_weth_rejected() {
        // path[last] is not WETH → should be rejected
        let call = IUniswapV2Router::swapExactTokensForETHCall {
            amountIn: U256::from(10_000u64),
            amountOutMin: U256::from(9_500u64),
            path: vec![WETH, USDC], // wrong: path[last] should be WETH
            to: Address::ZERO,
            deadline: U256::from(1_700_000_000u64),
        };
        let data = Bytes::from(call.abi_encode());
        assert!(matches!(
            validate_swap_calldata(&Some(data), RouterVersion::V2, SupportedChainId::Ethereum),
            SwapValidation::MalformedArgs { name, reason }
                if name == "swapExactTokensForETH" && reason.contains("wrapped native token")
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
            validate_swap_calldata(&Some(data), RouterVersion::V3, SupportedChainId::Ethereum),
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
            validate_swap_calldata(&Some(data), RouterVersion::V3, SupportedChainId::Ethereum),
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
        match validate_swap_calldata(&Some(data), RouterVersion::V3, SupportedChainId::Ethereum) {
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
