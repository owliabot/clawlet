//! Calldata validation for `send_raw` — only allows whitelisted functions
//! targeting known contract addresses.
//!
//! Supported targets:
//! - Uniswap V3 SwapRouter02 (`abi/ISwapRouter.json`)
//! - Uniswap V2 Router02 (`abi/IUniswapV2Router.json`)
//! - WETH/WBNB/WMATIC (`abi/IWETH.json`)
//! - Uniswap V3 NonfungiblePositionManager (`abi/INonfungiblePositionManager.json`)
//! - ERC-20 tokens (transfer, approve, transferFrom, permit)

use alloy::primitives::{address, Address, Bytes, U256};
use alloy::sol;
use alloy::sol_types::SolInterface;
use clawlet_core::chain::SupportedChainId;

use crate::abi::IERC20;

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

// Load WETH interface from ABI JSON.
sol!(
    #[sol(abi)]
    IWETH,
    "abi/IWETH.json"
);

// Load UniswapV3 NonfungiblePositionManager interface from ABI JSON.
sol!(
    #[sol(abi)]
    INonfungiblePositionManager,
    "abi/INonfungiblePositionManager.json"
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

/// Identified target contract type for `send_raw` validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendRawTarget {
    /// Uniswap V3 SwapRouter02.
    UniswapV3Router,
    /// Uniswap V2 Router02.
    UniswapV2Router,
    /// Wrapped native token (WETH/WBNB/WMATIC) — also supports ERC-20 operations.
    Weth,
    /// Uniswap V3 NonfungiblePositionManager.
    NftPositionManager,
    /// ERC-20 token (transfer, approve, transferFrom, permit).
    Erc20Token,
}

/// Identify the target contract type from a `to` address and chain.
///
/// `allowed_tokens` is the policy's allowed token list; when non-empty,
/// only addresses in this list can be identified as `Erc20Token`.
/// When empty, all unknown addresses are treated as potential ERC-20 tokens.
///
/// Returns `None` if the address is not a known contract and not in the
/// allowed token list.
pub fn identify_target(
    to: Address,
    chain: SupportedChainId,
    allowed_tokens: &[String],
) -> Option<SendRawTarget> {
    if to == swap_router_v3_address(chain) {
        Some(SendRawTarget::UniswapV3Router)
    } else if to == swap_router_v2_address(chain) {
        Some(SendRawTarget::UniswapV2Router)
    } else if to == wrapped_native_address(chain) {
        Some(SendRawTarget::Weth)
    } else if to == nft_position_manager_address(chain) {
        Some(SendRawTarget::NftPositionManager)
    } else {
        // Check if target is in allowed token list → ERC-20 token
        let addr_str = format!("{to}");
        let is_allowed = allowed_tokens.is_empty()
            || allowed_tokens
                .iter()
                .any(|t| t.eq_ignore_ascii_case(&addr_str));
        if is_allowed {
            Some(SendRawTarget::Erc20Token)
        } else {
            None
        }
    }
}

/// NonfungiblePositionManager addresses per chain (Uniswap V3 official deployments).
///
/// Source: <https://docs.uniswap.org/contracts/v3/reference/deployments>
pub fn nft_position_manager_address(chain: SupportedChainId) -> Address {
    match chain {
        SupportedChainId::Ethereum
        | SupportedChainId::Optimism
        | SupportedChainId::Polygon
        | SupportedChainId::Arbitrum => {
            address!("C36442b4a4522E871399CD717aBDD847Ab11FE88")
        }
        SupportedChainId::Base => address!("03a520b32C04BF3bEEf7BEb72E919cf822Ed34f1"),
        SupportedChainId::Bnb => address!("7b8A01B39D58278b5DE7e48c8449c9f4F5170613"),
    }
}

/// Parsed NonfungiblePositionManager parameters for policy checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NftPositionParams {
    /// Function name (e.g. "mint", "increaseLiquidity").
    pub function: String,
    /// First token address (only present for `mint`).
    pub token0: Option<Address>,
    /// Second token address (only present for `mint`).
    pub token1: Option<Address>,
    /// Position token ID (present for all except `mint`).
    pub token_id: Option<U256>,
}

/// Result of validating NonfungiblePositionManager calldata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NftPositionValidation {
    /// The calldata is a valid, ABI-decodable NFT position manager call.
    Allowed(NftPositionParams),
    /// The calldata is missing or too short to contain a function selector.
    NoSelector,
    /// The function selector is not one of the allowed position manager functions.
    Denied { selector: [u8; 4] },
    /// The function selector matches but ABI decoding failed (malformed args).
    MalformedArgs { name: String, reason: String },
}

/// Try to identify a known NonfungiblePositionManager function from a 4-byte selector.
///
/// Selectors:
/// - mint:               0x88316456
/// - increaseLiquidity:  0x219f5d17
/// - decreaseLiquidity:  0x0c49ccbe
/// - collect:            0xfc6f7865
/// - burn:               0x42966c68
fn selector_name_nft_position(selector: [u8; 4]) -> Option<&'static str> {
    match selector {
        [0x88, 0x31, 0x64, 0x56] => Some("mint"),
        [0x21, 0x9f, 0x5d, 0x17] => Some("increaseLiquidity"),
        [0x0c, 0x49, 0xcc, 0xbe] => Some("decreaseLiquidity"),
        [0xfc, 0x6f, 0x78, 0x65] => Some("collect"),
        [0x42, 0x96, 0x6c, 0x68] => Some("burn"),
        _ => None,
    }
}

/// Validate NonfungiblePositionManager calldata.
///
/// Whitelists: mint, increaseLiquidity, decreaseLiquidity, collect, burn.
/// For `mint`, token0 and token1 are extracted for policy checks.
/// For other operations, only tokenId is available (tokens were validated at mint time).
pub fn validate_nft_position_calldata(data: &Option<Bytes>) -> NftPositionValidation {
    let data = match data {
        Some(d) if d.len() >= 4 => d,
        _ => return NftPositionValidation::NoSelector,
    };
    let selector: [u8; 4] = [data[0], data[1], data[2], data[3]];

    match INonfungiblePositionManager::INonfungiblePositionManagerCalls::abi_decode(data) {
        Ok(call) => {
            let params = match &call {
                INonfungiblePositionManager::INonfungiblePositionManagerCalls::mint(c) => {
                    NftPositionParams {
                        function: "mint".into(),
                        token0: Some(c.params.token0),
                        token1: Some(c.params.token1),
                        token_id: None,
                    }
                }
                INonfungiblePositionManager::INonfungiblePositionManagerCalls::increaseLiquidity(c) => {
                    NftPositionParams {
                        function: "increaseLiquidity".into(),
                        token0: None,
                        token1: None,
                        token_id: Some(c.params.tokenId),
                    }
                }
                INonfungiblePositionManager::INonfungiblePositionManagerCalls::decreaseLiquidity(c) => {
                    NftPositionParams {
                        function: "decreaseLiquidity".into(),
                        token0: None,
                        token1: None,
                        token_id: Some(c.params.tokenId),
                    }
                }
                INonfungiblePositionManager::INonfungiblePositionManagerCalls::collect(c) => {
                    NftPositionParams {
                        function: "collect".into(),
                        token0: None,
                        token1: None,
                        token_id: Some(c.params.tokenId),
                    }
                }
                INonfungiblePositionManager::INonfungiblePositionManagerCalls::burn(c) => {
                    NftPositionParams {
                        function: "burn".into(),
                        token0: None,
                        token1: None,
                        token_id: Some(c.tokenId),
                    }
                }
                // All other NonfungiblePositionManager functions (approve, transferFrom,
                // multicall, permit, sweepToken, etc.) are valid ABI but not whitelisted.
                _ => {
                    return NftPositionValidation::Denied { selector };
                }
            };
            NftPositionValidation::Allowed(params)
        }
        Err(err) => {
            if let Some(name) = selector_name_nft_position(selector) {
                NftPositionValidation::MalformedArgs {
                    name: name.to_string(),
                    reason: err.to_string(),
                }
            } else {
                NftPositionValidation::Denied { selector }
            }
        }
    }
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

/// Try to identify a known liquidity function name from a 4-byte selector.
///
/// UniswapV2 Router02 liquidity selectors:
/// - addLiquidity:    0xe8e33700
/// - addLiquidityETH: 0xf305d719
/// - removeLiquidity: 0xbaa2abde
/// - removeLiquidityETH: 0x02751cec
fn selector_name_liquidity(selector: [u8; 4]) -> Option<&'static str> {
    match selector {
        [0xe8, 0xe3, 0x37, 0x00] => Some("addLiquidity"),
        [0xf3, 0x05, 0xd7, 0x19] => Some("addLiquidityETH"),
        [0xba, 0xa2, 0xab, 0xde] => Some("removeLiquidity"),
        [0x02, 0x75, 0x1c, 0xec] => Some("removeLiquidityETH"),
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

/// Parsed liquidity parameters for policy checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiquidityParams {
    /// Function name (e.g. "addLiquidity").
    pub function: String,
    /// First token address in the pool.
    pub token_a: Address,
    /// Second token address in the pool.
    pub token_b: Address,
    /// Amount for token A (amountADesired for add, amountAMin for remove).
    pub amount_a: U256,
    /// Amount for token B (amountBDesired for add, amountBMin for remove).
    pub amount_b: U256,
}

/// Result of validating liquidity calldata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiquidityValidation {
    /// The calldata is a valid, ABI-decodable Uniswap liquidity call.
    Allowed(LiquidityParams),
    /// The calldata is missing or too short to contain a function selector.
    NoSelector,
    /// The function selector is not one of the allowed liquidity functions.
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

/// Validate calldata against the identified router target.
///
/// Uses the target type (determined from the `to` address) to decode
/// calldata with the correct ABI, avoiding cross-version false matches.
/// For V2, `chain` is used to validate WETH endpoints in ETH-path swaps.
pub fn validate_swap_calldata(
    data: &Option<Bytes>,
    target: SendRawTarget,
    chain: SupportedChainId,
) -> SwapValidation {
    let data = match data {
        Some(d) if d.len() >= 4 => d,
        _ => return SwapValidation::NoSelector,
    };
    let selector: [u8; 4] = [data[0], data[1], data[2], data[3]];

    match target {
        SendRawTarget::UniswapV3Router => validate_v3(data, selector),
        SendRawTarget::UniswapV2Router => validate_v2(data, selector, chain),
        _ => SwapValidation::Denied { selector },
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
/// - **deposit()** (wrap): no args (or empty/None calldata), value > 0
/// - **withdraw(uint256)** (unwrap): one uint256 arg
///
/// Uses alloy's `sol!` macro with the WETH ABI JSON for calldata decoding.
/// Only deposit and withdraw functions are allowed; other functions (approve, transfer, etc.) are rejected.
pub fn validate_weth_calldata(data: &Option<Bytes>, value: Option<U256>) -> WethValidation {
    // None or empty calldata → fallback deposit (WETH9 fallback function is payable)
    let data = match data {
        Some(d) if !d.is_empty() => d,
        _ => {
            let amount = value.unwrap_or(U256::ZERO);
            if amount.is_zero() {
                return WethValidation::Invalid {
                    reason: "empty calldata with zero value is not a valid WETH operation".into(),
                };
            }
            return WethValidation::Wrap(amount);
        }
    };

    // ABI decode — handles selector extraction, length validation, and argument parsing
    match IWETH::IWETHCalls::abi_decode(data) {
        Ok(call) => match call {
            IWETH::IWETHCalls::deposit(_) => {
                let amount = value.unwrap_or(U256::ZERO);
                if amount.is_zero() {
                    return WethValidation::Invalid {
                        reason: "deposit() requires value > 0".into(),
                    };
                }
                WethValidation::Wrap(amount)
            }
            IWETH::IWETHCalls::withdraw(w) => {
                if w.wad.is_zero() {
                    return WethValidation::Invalid {
                        reason: "withdraw amount must be > 0".into(),
                    };
                }
                WethValidation::Unwrap(w.wad)
            }
            // Other WETH functions (approve, transfer, transferFrom, etc.) are not allowed
            _ => WethValidation::Invalid {
                reason: "only deposit and withdraw functions are allowed for WETH operations"
                    .into(),
            },
        },
        Err(e) => WethValidation::Invalid {
            reason: format!("invalid WETH calldata: {e}"),
        },
    }
}

/// Validate UniswapV2 Router liquidity calldata.
///
/// Whitelists: addLiquidity, addLiquidityETH, removeLiquidity, removeLiquidityETH.
/// For ETH variants, the wrapped native token is used as token_b.
/// All other V2 Router functions are denied.
pub fn validate_liquidity_calldata(
    data: &Option<Bytes>,
    chain: SupportedChainId,
) -> LiquidityValidation {
    let data = match data {
        Some(d) if d.len() >= 4 => d,
        _ => return LiquidityValidation::NoSelector,
    };
    let selector: [u8; 4] = [data[0], data[1], data[2], data[3]];
    let weth = wrapped_native_address(chain);

    match IUniswapV2Router::IUniswapV2RouterCalls::abi_decode(data) {
        Ok(call) => {
            let params = match &call {
                IUniswapV2Router::IUniswapV2RouterCalls::addLiquidity(c) => LiquidityParams {
                    function: "addLiquidity".into(),
                    token_a: c.tokenA,
                    token_b: c.tokenB,
                    amount_a: c.amountADesired,
                    amount_b: c.amountBDesired,
                },
                IUniswapV2Router::IUniswapV2RouterCalls::addLiquidityETH(c) => LiquidityParams {
                    function: "addLiquidityETH".into(),
                    token_a: c.token,
                    token_b: weth,
                    amount_a: c.amountTokenDesired,
                    amount_b: U256::ZERO, // ETH sent as msg.value
                },
                IUniswapV2Router::IUniswapV2RouterCalls::removeLiquidity(c) => LiquidityParams {
                    function: "removeLiquidity".into(),
                    token_a: c.tokenA,
                    token_b: c.tokenB,
                    amount_a: c.amountAMin,
                    amount_b: c.amountBMin,
                },
                IUniswapV2Router::IUniswapV2RouterCalls::removeLiquidityETH(c) => LiquidityParams {
                    function: "removeLiquidityETH".into(),
                    token_a: c.token,
                    token_b: weth,
                    amount_a: c.amountTokenMin,
                    amount_b: c.amountETHMin,
                },
                // All other V2 Router functions are not whitelisted for liquidity.
                _ => {
                    return LiquidityValidation::Denied { selector };
                }
            };
            LiquidityValidation::Allowed(params)
        }
        Err(err) => {
            if let Some(name) = selector_name_liquidity(selector) {
                LiquidityValidation::MalformedArgs {
                    name: name.to_string(),
                    reason: err.to_string(),
                }
            } else {
                LiquidityValidation::Denied { selector }
            }
        }
    }
}

// ---- ERC-20 token validation ----

/// Parsed ERC-20 call parameters for policy checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Erc20Params {
    /// Function name (e.g. "transfer", "approve", "transferFrom", "permit").
    pub function: String,
    /// The spender (approve/permit) or recipient (transfer/transferFrom).
    pub spender_or_recipient: Address,
    /// The amount/value.
    pub amount: U256,
    /// For transferFrom/permit: the `from`/`owner` address.
    pub from: Option<Address>,
}

/// Result of validating ERC-20 calldata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Erc20Validation {
    /// The calldata is a valid, ABI-decodable ERC-20 call.
    Allowed(Erc20Params),
    /// The calldata is missing or too short to contain a function selector.
    NoSelector,
    /// The function selector is not one of the allowed ERC-20 functions.
    Denied { selector: [u8; 4] },
    /// The function selector matches but ABI decoding failed (malformed args).
    MalformedArgs { name: String, reason: String },
}

/// Try to identify a known ERC-20 function name from a 4-byte selector.
///
/// Selectors:
/// - transfer:     0xa9059cbb
/// - approve:      0x095ea7b3
/// - transferFrom: 0x23b872dd
/// - permit:       0xd505accf
fn selector_name_erc20(selector: [u8; 4]) -> Option<&'static str> {
    match selector {
        [0xa9, 0x05, 0x9c, 0xbb] => Some("transfer"),
        [0x09, 0x5e, 0xa7, 0xb3] => Some("approve"),
        [0x23, 0xb8, 0x72, 0xdd] => Some("transferFrom"),
        [0xd5, 0x05, 0xac, 0xcf] => Some("permit"),
        _ => None,
    }
}

/// Validate ERC-20 token calldata.
///
/// Whitelists: transfer, approve, transferFrom, permit.
pub fn validate_erc20_calldata(data: &Option<Bytes>) -> Erc20Validation {
    let data = match data {
        Some(d) if d.len() >= 4 => d,
        _ => return Erc20Validation::NoSelector,
    };
    let selector: [u8; 4] = [data[0], data[1], data[2], data[3]];

    match IERC20::IERC20Calls::abi_decode(data) {
        Ok(call) => {
            let params = match &call {
                IERC20::IERC20Calls::transfer(c) => Erc20Params {
                    function: "transfer".into(),
                    spender_or_recipient: c._to,
                    amount: c._value,
                    from: None,
                },
                IERC20::IERC20Calls::approve(c) => Erc20Params {
                    function: "approve".into(),
                    spender_or_recipient: c._spender,
                    amount: c._value,
                    from: None,
                },
                IERC20::IERC20Calls::transferFrom(c) => Erc20Params {
                    function: "transferFrom".into(),
                    spender_or_recipient: c._to,
                    amount: c._value,
                    from: Some(c._from),
                },
                IERC20::IERC20Calls::permit(c) => Erc20Params {
                    function: "permit".into(),
                    spender_or_recipient: c.spender,
                    amount: c.value,
                    from: Some(c.owner),
                },
                // Other IERC20 functions (balanceOf, allowance, name, symbol, decimals)
                // are read-only and not allowed via send_raw.
                _ => {
                    return Erc20Validation::Denied { selector };
                }
            };
            Erc20Validation::Allowed(params)
        }
        Err(err) => {
            if let Some(name) = selector_name_erc20(selector) {
                Erc20Validation::MalformedArgs {
                    name: name.to_string(),
                    reason: err.to_string(),
                }
            } else {
                Erc20Validation::Denied { selector }
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
        // Ethereum V3
        assert_eq!(
            identify_target(
                address!("68b3465833fb72A70ecDF485E0e4C7bD8665Fc45"),
                SupportedChainId::Ethereum,
                &[]
            ),
            Some(SendRawTarget::UniswapV3Router)
        );
        // Ethereum V2
        assert_eq!(
            identify_target(
                address!("7a250d5630B4cF539739dF2C5dAcb4c659F2488D"),
                SupportedChainId::Ethereum,
                &[]
            ),
            Some(SendRawTarget::UniswapV2Router)
        );

        // Optimism V3
        assert_eq!(
            identify_target(
                address!("68b3465833fb72A70ecDF485E0e4C7bD8665Fc45"),
                SupportedChainId::Optimism,
                &[]
            ),
            Some(SendRawTarget::UniswapV3Router)
        );
        // Optimism V2
        assert_eq!(
            identify_target(
                address!("4A7b5Da61326A6379179b40d00F57E5bbDC962c2"),
                SupportedChainId::Optimism,
                &[]
            ),
            Some(SendRawTarget::UniswapV2Router)
        );

        // Polygon V3
        assert_eq!(
            identify_target(
                address!("68b3465833fb72A70ecDF485E0e4C7bD8665Fc45"),
                SupportedChainId::Polygon,
                &[]
            ),
            Some(SendRawTarget::UniswapV3Router)
        );
        // Polygon V2
        assert_eq!(
            identify_target(
                address!("edf6066a2b290C185783862C7F4776A2C8077AD1"),
                SupportedChainId::Polygon,
                &[]
            ),
            Some(SendRawTarget::UniswapV2Router)
        );

        // Arbitrum V3
        assert_eq!(
            identify_target(
                address!("68b3465833fb72A70ecDF485E0e4C7bD8665Fc45"),
                SupportedChainId::Arbitrum,
                &[]
            ),
            Some(SendRawTarget::UniswapV3Router)
        );
        // Arbitrum V2
        assert_eq!(
            identify_target(
                address!("4752ba5DBc23f44D87826276BF6Fd6b1C372aD24"),
                SupportedChainId::Arbitrum,
                &[]
            ),
            Some(SendRawTarget::UniswapV2Router)
        );

        // Base V3
        assert_eq!(
            identify_target(
                address!("2626664c2603336E57B271c5C0b26F421741e481"),
                SupportedChainId::Base,
                &[]
            ),
            Some(SendRawTarget::UniswapV3Router)
        );
        // Base V2
        assert_eq!(
            identify_target(
                address!("4752ba5DBc23f44D87826276BF6Fd6b1C372aD24"),
                SupportedChainId::Base,
                &[]
            ),
            Some(SendRawTarget::UniswapV2Router)
        );

        // BNB V3
        assert_eq!(
            identify_target(
                address!("B971eF87ede563556b2ED4b1C0b0019111Dd85d2"),
                SupportedChainId::Bnb,
                &[]
            ),
            Some(SendRawTarget::UniswapV3Router)
        );
        // BNB V2
        assert_eq!(
            identify_target(
                address!("4752ba5DBc23f44D87826276BF6Fd6b1C372aD24"),
                SupportedChainId::Bnb,
                &[]
            ),
            Some(SendRawTarget::UniswapV2Router)
        );
    }

    #[test]
    fn wrong_router_denied() {
        let random = address!("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
        // Non-empty allowed list that doesn't include the random address
        let allowed = vec!["USDC".to_string()];
        for chain in SupportedChainId::ALL {
            assert!(
                identify_target(random, chain, &allowed).is_none(),
                "random address should be denied on {chain}"
            );
        }
    }

    #[test]
    fn wrong_router_erc20_fallback() {
        // With empty allowed list (all allowed), random address → Erc20Token
        let random = address!("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
        for chain in SupportedChainId::ALL {
            assert_eq!(
                identify_target(random, chain, &[]),
                Some(SendRawTarget::Erc20Token),
                "random address with empty allowed list should be Erc20Token on {chain}"
            );
        }
    }

    #[test]
    fn old_swap_router_v1_denied() {
        // The old SwapRouter (0xE592...) should NOT be allowed
        let v1_router = address!("E592427A0AEce92De3Edee1F18E0157C05861564");
        let allowed = vec!["USDC".to_string()];
        for chain in SupportedChainId::ALL {
            assert!(
                identify_target(v1_router, chain, &allowed).is_none(),
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
            SendRawTarget::UniswapV3Router,
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
            SendRawTarget::UniswapV3Router,
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
            SendRawTarget::UniswapV3Router,
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
            SendRawTarget::UniswapV3Router,
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
            validate_swap_calldata(&Some(data), SendRawTarget::UniswapV3Router, SupportedChainId::Ethereum),
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
            validate_swap_calldata(
                &Some(data),
                SendRawTarget::UniswapV3Router,
                SupportedChainId::Ethereum
            ),
            SwapValidation::Denied { .. }
        ));
    }

    #[test]
    fn empty_data_no_selector() {
        assert_eq!(
            validate_swap_calldata(
                &None,
                SendRawTarget::UniswapV3Router,
                SupportedChainId::Ethereum
            ),
            SwapValidation::NoSelector
        );
        assert_eq!(
            validate_swap_calldata(
                &Some(Bytes::new()),
                SendRawTarget::UniswapV3Router,
                SupportedChainId::Ethereum
            ),
            SwapValidation::NoSelector
        );
    }

    #[test]
    fn short_data_no_selector() {
        let data = Bytes::from(vec![0x04, 0xe4, 0x5a]);
        assert_eq!(
            validate_swap_calldata(
                &Some(data),
                SendRawTarget::UniswapV3Router,
                SupportedChainId::Ethereum
            ),
            SwapValidation::NoSelector
        );
    }

    #[test]
    fn correct_selector_but_malformed_args() {
        // exactInputSingle selector (0x04e45aaf) with garbage
        let data = Bytes::from(vec![0x04, 0xe4, 0x5a, 0xaf, 0xff, 0xff]);
        assert!(matches!(
            validate_swap_calldata(&Some(data), SendRawTarget::UniswapV3Router, SupportedChainId::Ethereum),
            SwapValidation::MalformedArgs { name, .. } if name == "exactInputSingle"
        ));
    }

    #[test]
    fn selector_only_is_malformed() {
        // exactInput selector (0xb858183f) with no args
        let data = Bytes::from(vec![0xb8, 0x58, 0x18, 0x3f]);
        assert!(matches!(
            validate_swap_calldata(&Some(data), SendRawTarget::UniswapV3Router, SupportedChainId::Ethereum),
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
            SendRawTarget::UniswapV2Router,
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
            SendRawTarget::UniswapV2Router,
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
            SendRawTarget::UniswapV2Router,
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
            validate_swap_calldata(&Some(data), SendRawTarget::UniswapV2Router, SupportedChainId::Ethereum),
            SwapValidation::MalformedArgs { name, .. } if name == "swapExactTokensForTokens"
        ));
    }

    #[test]
    fn v2_eth_for_tokens_selector_only_is_malformed() {
        // swapExactETHForTokens selector (0x7ff36ab5) with no args
        let data = Bytes::from(vec![0x7f, 0xf3, 0x6a, 0xb5]);
        assert!(matches!(
            validate_swap_calldata(&Some(data), SendRawTarget::UniswapV2Router, SupportedChainId::Ethereum),
            SwapValidation::MalformedArgs { name, .. } if name == "swapExactETHForTokens"
        ));
    }

    #[test]
    fn v2_tokens_for_eth_selector_only_is_malformed() {
        // swapExactTokensForETH selector (0x18cbafe5) with no args
        let data = Bytes::from(vec![0x18, 0xcb, 0xaf, 0xe5]);
        assert!(matches!(
            validate_swap_calldata(&Some(data), SendRawTarget::UniswapV2Router, SupportedChainId::Ethereum),
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
            validate_swap_calldata(&Some(data), SendRawTarget::UniswapV2Router, SupportedChainId::Ethereum),
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
            validate_swap_calldata(&Some(data), SendRawTarget::UniswapV2Router, SupportedChainId::Ethereum),
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
            validate_swap_calldata(&Some(data), SendRawTarget::UniswapV2Router, SupportedChainId::Ethereum),
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
            validate_swap_calldata(&Some(data), SendRawTarget::UniswapV2Router, SupportedChainId::Ethereum),
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
            validate_swap_calldata(&Some(data), SendRawTarget::UniswapV2Router, SupportedChainId::Ethereum),
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
            validate_swap_calldata(&Some(data), SendRawTarget::UniswapV2Router, SupportedChainId::Ethereum),
            SwapValidation::MalformedArgs { name, reason } if name == "swapExactTokensForETH" && reason.contains("at least 2")
        ));
    }

    // ---- Cross-version mismatch tests ----

    #[test]
    fn v2_calldata_with_v3_version_denied() {
        // V2 swapExactTokensForTokens calldata validated as V3 → Denied
        let data = encode_swap_exact_tokens_for_tokens();
        assert!(matches!(
            validate_swap_calldata(
                &Some(data),
                SendRawTarget::UniswapV3Router,
                SupportedChainId::Ethereum
            ),
            SwapValidation::Denied { .. }
        ));
    }

    #[test]
    fn v3_calldata_with_v2_version_denied() {
        // V3 exactInputSingle calldata validated as V2 → Denied
        let data = encode_exact_input_single();
        assert!(matches!(
            validate_swap_calldata(
                &Some(data),
                SendRawTarget::UniswapV2Router,
                SupportedChainId::Ethereum
            ),
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
            validate_swap_calldata(&Some(data), SendRawTarget::UniswapV2Router, SupportedChainId::Ethereum),
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
            validate_swap_calldata(&Some(data), SendRawTarget::UniswapV2Router, SupportedChainId::Ethereum),
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
            validate_swap_calldata(&Some(data), SendRawTarget::UniswapV3Router, SupportedChainId::Ethereum),
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
            validate_swap_calldata(&Some(data), SendRawTarget::UniswapV3Router, SupportedChainId::Ethereum),
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
        match validate_swap_calldata(
            &Some(data),
            SendRawTarget::UniswapV3Router,
            SupportedChainId::Ethereum,
        ) {
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

    // ---- WETH validation tests ----

    #[test]
    fn weth_deposit_with_selector_and_value_valid() {
        // deposit() selector only + value > 0 → Wrap
        let call = IWETH::depositCall {};
        let data = Some(Bytes::from(call.abi_encode()));
        let value = Some(U256::from(1_000_000_000_000_000_000u64));
        match validate_weth_calldata(&data, value) {
            WethValidation::Wrap(amount) => {
                assert_eq!(amount, U256::from(1_000_000_000_000_000_000u64));
            }
            other => panic!("expected Wrap, got {:?}", other),
        }
    }

    #[test]
    fn weth_deposit_with_selector_no_value_invalid() {
        // deposit() selector only + value == 0 → Invalid
        let call = IWETH::depositCall {};
        let data = Some(Bytes::from(call.abi_encode()));
        let value = Some(U256::ZERO);
        assert!(matches!(
            validate_weth_calldata(&data, value),
            WethValidation::Invalid { .. }
        ));
    }

    #[test]
    fn weth_empty_calldata_with_value_wrap() {
        // empty calldata + value > 0 → Wrap (fallback)
        let data = Some(Bytes::new());
        let value = Some(U256::from(500_000_000_000_000_000u64));
        match validate_weth_calldata(&data, value) {
            WethValidation::Wrap(amount) => {
                assert_eq!(amount, U256::from(500_000_000_000_000_000u64));
            }
            other => panic!("expected Wrap, got {:?}", other),
        }
    }

    #[test]
    fn weth_none_calldata_with_value_wrap() {
        // None calldata + value > 0 → Wrap (fallback)
        let value = Some(U256::from(250_000_000_000_000_000u64));
        match validate_weth_calldata(&None, value) {
            WethValidation::Wrap(amount) => {
                assert_eq!(amount, U256::from(250_000_000_000_000_000u64));
            }
            other => panic!("expected Wrap, got {:?}", other),
        }
    }

    #[test]
    fn weth_empty_calldata_no_value_invalid() {
        // empty/None + value == 0 → Invalid
        assert!(matches!(
            validate_weth_calldata(&Some(Bytes::new()), Some(U256::ZERO)),
            WethValidation::Invalid { .. }
        ));
        assert!(matches!(
            validate_weth_calldata(&None, Some(U256::ZERO)),
            WethValidation::Invalid { .. }
        ));
        assert!(matches!(
            validate_weth_calldata(&Some(Bytes::new()), None),
            WethValidation::Invalid { .. }
        ));
        assert!(matches!(
            validate_weth_calldata(&None, None),
            WethValidation::Invalid { .. }
        ));
    }

    #[test]
    fn weth_withdraw_with_valid_amount_unwrap() {
        // withdraw with valid amount → Unwrap
        let call = IWETH::withdrawCall {
            wad: U256::from(1_000_000_000_000_000_000u64),
        };
        let data = Some(Bytes::from(call.abi_encode()));
        match validate_weth_calldata(&data, None) {
            WethValidation::Unwrap(amount) => {
                assert_eq!(amount, U256::from(1_000_000_000_000_000_000u64));
            }
            other => panic!("expected Unwrap, got {:?}", other),
        }
    }

    #[test]
    fn weth_withdraw_with_zero_amount_invalid() {
        // withdraw with amount == 0 → Invalid
        let call = IWETH::withdrawCall { wad: U256::ZERO };
        let data = Some(Bytes::from(call.abi_encode()));
        assert!(matches!(
            validate_weth_calldata(&data, None),
            WethValidation::Invalid { .. }
        ));
    }

    #[test]
    fn weth_unknown_selector_invalid() {
        // unknown selector → Invalid
        let data = Some(Bytes::from(vec![0xde, 0xad, 0xbe, 0xef, 0x00, 0x00]));
        assert!(matches!(
            validate_weth_calldata(&data, None),
            WethValidation::Invalid { .. }
        ));
    }

    #[test]
    fn weth_approve_selector_invalid() {
        // WETH approve → Invalid (not allowed)
        let call = IWETH::approveCall {
            guy: Address::ZERO,
            wad: U256::from(1000u64),
        };
        let data = Some(Bytes::from(call.abi_encode()));
        assert!(matches!(
            validate_weth_calldata(&data, None),
            WethValidation::Invalid { reason } if reason.contains("only deposit and withdraw")
        ));
    }

    #[test]
    fn weth_transfer_selector_invalid() {
        // WETH transfer → Invalid (not allowed)
        let call = IWETH::transferCall {
            dst: Address::ZERO,
            wad: U256::from(1000u64),
        };
        let data = Some(Bytes::from(call.abi_encode()));
        assert!(matches!(
            validate_weth_calldata(&data, None),
            WethValidation::Invalid { reason } if reason.contains("only deposit and withdraw")
        ));
    }

    #[test]
    fn weth_short_calldata_invalid() {
        // short calldata (1-3 bytes) → Invalid
        assert!(matches!(
            validate_weth_calldata(&Some(Bytes::from(vec![0xd0])), None),
            WethValidation::Invalid { .. }
        ));
        assert!(matches!(
            validate_weth_calldata(&Some(Bytes::from(vec![0xd0, 0xe3])), None),
            WethValidation::Invalid { .. }
        ));
        assert!(matches!(
            validate_weth_calldata(&Some(Bytes::from(vec![0xd0, 0xe3, 0x0d])), None),
            WethValidation::Invalid { .. }
        ));
    }

    #[test]
    fn weth_malformed_withdraw_invalid() {
        // malformed withdraw (selector only, wrong length) → Invalid
        let data = Some(Bytes::from(vec![0x2e, 0x1a, 0x7d, 0x4d]));
        assert!(matches!(
            validate_weth_calldata(&data, None),
            WethValidation::Invalid { .. }
        ));
    }

    // ---- Liquidity validation tests ----

    const DAI: Address = address!("6B175474E89094C44Da98b954EedeAC495271d0F");

    fn encode_add_liquidity() -> Bytes {
        let call = IUniswapV2Router::addLiquidityCall {
            tokenA: USDC,
            tokenB: DAI,
            amountADesired: U256::from(1_000_000u64),
            amountBDesired: U256::from(1_000_000_000_000_000_000u64),
            amountAMin: U256::from(900_000u64),
            amountBMin: U256::from(900_000_000_000_000_000u64),
            to: Address::ZERO,
            deadline: U256::from(1_700_000_000u64),
        };
        Bytes::from(call.abi_encode())
    }

    fn encode_add_liquidity_eth() -> Bytes {
        let call = IUniswapV2Router::addLiquidityETHCall {
            token: USDC,
            amountTokenDesired: U256::from(1_000_000u64),
            amountTokenMin: U256::from(900_000u64),
            amountETHMin: U256::from(900_000_000_000_000_000u64),
            to: Address::ZERO,
            deadline: U256::from(1_700_000_000u64),
        };
        Bytes::from(call.abi_encode())
    }

    fn encode_remove_liquidity() -> Bytes {
        let call = IUniswapV2Router::removeLiquidityCall {
            tokenA: USDC,
            tokenB: DAI,
            liquidity: U256::from(500_000u64),
            amountAMin: U256::from(450_000u64),
            amountBMin: U256::from(450_000_000_000_000_000u64),
            to: Address::ZERO,
            deadline: U256::from(1_700_000_000u64),
        };
        Bytes::from(call.abi_encode())
    }

    fn encode_remove_liquidity_eth() -> Bytes {
        let call = IUniswapV2Router::removeLiquidityETHCall {
            token: USDC,
            liquidity: U256::from(500_000u64),
            amountTokenMin: U256::from(450_000u64),
            amountETHMin: U256::from(450_000_000_000_000_000u64),
            to: Address::ZERO,
            deadline: U256::from(1_700_000_000u64),
        };
        Bytes::from(call.abi_encode())
    }

    #[test]
    fn add_liquidity_valid() {
        match validate_liquidity_calldata(&Some(encode_add_liquidity()), SupportedChainId::Ethereum)
        {
            LiquidityValidation::Allowed(p) => {
                assert_eq!(p.function, "addLiquidity");
                assert_eq!(p.token_a, USDC);
                assert_eq!(p.token_b, DAI);
                assert_eq!(p.amount_a, U256::from(1_000_000u64));
                assert_eq!(p.amount_b, U256::from(1_000_000_000_000_000_000u64));
            }
            other => panic!("expected Allowed, got {:?}", other),
        }
    }

    #[test]
    fn add_liquidity_eth_valid() {
        match validate_liquidity_calldata(
            &Some(encode_add_liquidity_eth()),
            SupportedChainId::Ethereum,
        ) {
            LiquidityValidation::Allowed(p) => {
                assert_eq!(p.function, "addLiquidityETH");
                assert_eq!(p.token_a, USDC);
                assert_eq!(p.token_b, WETH); // wrapped native for Ethereum
                assert_eq!(p.amount_a, U256::from(1_000_000u64));
                assert_eq!(p.amount_b, U256::ZERO); // ETH sent as msg.value
            }
            other => panic!("expected Allowed, got {:?}", other),
        }
    }

    #[test]
    fn add_liquidity_eth_uses_chain_weth() {
        // On Polygon, token_b should be WMATIC
        match validate_liquidity_calldata(
            &Some(encode_add_liquidity_eth()),
            SupportedChainId::Polygon,
        ) {
            LiquidityValidation::Allowed(p) => {
                assert_eq!(p.function, "addLiquidityETH");
                assert_eq!(p.token_b, wrapped_native_address(SupportedChainId::Polygon));
            }
            other => panic!("expected Allowed, got {:?}", other),
        }
    }

    #[test]
    fn remove_liquidity_valid() {
        match validate_liquidity_calldata(
            &Some(encode_remove_liquidity()),
            SupportedChainId::Ethereum,
        ) {
            LiquidityValidation::Allowed(p) => {
                assert_eq!(p.function, "removeLiquidity");
                assert_eq!(p.token_a, USDC);
                assert_eq!(p.token_b, DAI);
                assert_eq!(p.amount_a, U256::from(450_000u64));
                assert_eq!(p.amount_b, U256::from(450_000_000_000_000_000u64));
            }
            other => panic!("expected Allowed, got {:?}", other),
        }
    }

    #[test]
    fn remove_liquidity_eth_valid() {
        match validate_liquidity_calldata(
            &Some(encode_remove_liquidity_eth()),
            SupportedChainId::Ethereum,
        ) {
            LiquidityValidation::Allowed(p) => {
                assert_eq!(p.function, "removeLiquidityETH");
                assert_eq!(p.token_a, USDC);
                assert_eq!(p.token_b, WETH);
                assert_eq!(p.amount_a, U256::from(450_000u64));
                assert_eq!(p.amount_b, U256::from(450_000_000_000_000_000u64));
            }
            other => panic!("expected Allowed, got {:?}", other),
        }
    }

    #[test]
    fn liquidity_no_selector() {
        assert_eq!(
            validate_liquidity_calldata(&None, SupportedChainId::Ethereum),
            LiquidityValidation::NoSelector
        );
        assert_eq!(
            validate_liquidity_calldata(&Some(Bytes::new()), SupportedChainId::Ethereum),
            LiquidityValidation::NoSelector
        );
        assert_eq!(
            validate_liquidity_calldata(
                &Some(Bytes::from(vec![0xe8, 0xe3, 0x37])),
                SupportedChainId::Ethereum
            ),
            LiquidityValidation::NoSelector
        );
    }

    #[test]
    fn liquidity_unknown_selector_denied() {
        let data = Bytes::from(vec![0xde, 0xad, 0xbe, 0xef, 0x00, 0x00]);
        assert!(matches!(
            validate_liquidity_calldata(&Some(data), SupportedChainId::Ethereum),
            LiquidityValidation::Denied { selector } if selector == [0xde, 0xad, 0xbe, 0xef]
        ));
    }

    #[test]
    fn liquidity_swap_selectors_denied() {
        // Swap calldata should be denied by liquidity validation
        let data = encode_swap_exact_tokens_for_tokens();
        assert!(matches!(
            validate_liquidity_calldata(&Some(data), SupportedChainId::Ethereum),
            LiquidityValidation::Denied { .. }
        ));
    }

    #[test]
    fn liquidity_add_selector_only_malformed() {
        // addLiquidity selector (0xe8e33700) with no args
        let data = Bytes::from(vec![0xe8, 0xe3, 0x37, 0x00]);
        assert!(matches!(
            validate_liquidity_calldata(&Some(data), SupportedChainId::Ethereum),
            LiquidityValidation::MalformedArgs { name, .. } if name == "addLiquidity"
        ));
    }

    #[test]
    fn liquidity_add_eth_selector_only_malformed() {
        // addLiquidityETH selector (0xf305d719) with no args
        let data = Bytes::from(vec![0xf3, 0x05, 0xd7, 0x19]);
        assert!(matches!(
            validate_liquidity_calldata(&Some(data), SupportedChainId::Ethereum),
            LiquidityValidation::MalformedArgs { name, .. } if name == "addLiquidityETH"
        ));
    }

    #[test]
    fn liquidity_remove_selector_only_malformed() {
        // removeLiquidity selector (0xbaa2abde) with no args
        let data = Bytes::from(vec![0xba, 0xa2, 0xab, 0xde]);
        assert!(matches!(
            validate_liquidity_calldata(&Some(data), SupportedChainId::Ethereum),
            LiquidityValidation::MalformedArgs { name, .. } if name == "removeLiquidity"
        ));
    }

    #[test]
    fn liquidity_remove_eth_selector_only_malformed() {
        // removeLiquidityETH selector (0x02751cec) with no args
        let data = Bytes::from(vec![0x02, 0x75, 0x1c, 0xec]);
        assert!(matches!(
            validate_liquidity_calldata(&Some(data), SupportedChainId::Ethereum),
            LiquidityValidation::MalformedArgs { name, .. } if name == "removeLiquidityETH"
        ));
    }

    #[test]
    fn liquidity_add_with_garbage_malformed() {
        // addLiquidity selector + garbage
        let data = Bytes::from(vec![0xe8, 0xe3, 0x37, 0x00, 0xff, 0xff]);
        assert!(matches!(
            validate_liquidity_calldata(&Some(data), SupportedChainId::Ethereum),
            LiquidityValidation::MalformedArgs { name, .. } if name == "addLiquidity"
        ));
    }

    #[test]
    fn liquidity_non_whitelisted_v2_functions_denied() {
        // removeLiquidityWithPermit has a valid ABI decode but should be denied
        let call = IUniswapV2Router::removeLiquidityWithPermitCall {
            tokenA: USDC,
            tokenB: DAI,
            liquidity: U256::from(500_000u64),
            amountAMin: U256::from(1u64),
            amountBMin: U256::from(1u64),
            to: Address::ZERO,
            deadline: U256::from(1_700_000_000u64),
            approveMax: false,
            v: 27,
            r: alloy::primitives::B256::ZERO,
            s: alloy::primitives::B256::ZERO,
        };
        let data = Bytes::from(call.abi_encode());
        assert!(matches!(
            validate_liquidity_calldata(&Some(data), SupportedChainId::Ethereum),
            LiquidityValidation::Denied { .. }
        ));
    }

    // ---- NonfungiblePositionManager tests ----

    #[test]
    fn nft_pm_address_per_chain() {
        // Ethereum, Optimism, Polygon, Arbitrum share the same address
        let shared = address!("C36442b4a4522E871399CD717aBDD847Ab11FE88");
        assert_eq!(
            identify_target(shared, SupportedChainId::Ethereum, &[]),
            Some(SendRawTarget::NftPositionManager)
        );
        assert_eq!(
            identify_target(shared, SupportedChainId::Optimism, &[]),
            Some(SendRawTarget::NftPositionManager)
        );
        assert_eq!(
            identify_target(shared, SupportedChainId::Polygon, &[]),
            Some(SendRawTarget::NftPositionManager)
        );
        assert_eq!(
            identify_target(shared, SupportedChainId::Arbitrum, &[]),
            Some(SendRawTarget::NftPositionManager)
        );

        // Base has a different address
        assert_eq!(
            identify_target(
                address!("03a520b32C04BF3bEEf7BEb72E919cf822Ed34f1"),
                SupportedChainId::Base,
                &[]
            ),
            Some(SendRawTarget::NftPositionManager)
        );
        // BNB has a different address
        assert_eq!(
            identify_target(
                address!("7b8A01B39D58278b5DE7e48c8449c9f4F5170613"),
                SupportedChainId::Bnb,
                &[]
            ),
            Some(SendRawTarget::NftPositionManager)
        );

        // Random address should not match when allowed list is non-empty
        let random = address!("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
        let allowed = vec!["USDC".to_string()];
        for chain in SupportedChainId::ALL {
            assert!(
                identify_target(random, chain, &allowed).is_none(),
                "random address should not match on {chain}"
            );
        }
    }

    #[test]
    fn nft_pm_mint_valid() {
        let call = INonfungiblePositionManager::mintCall {
            params: INonfungiblePositionManager::MintParams {
                token0: WETH,
                token1: USDC,
                fee: Uint::from(3000u32),
                tickLower: alloy::primitives::Signed::try_from(-887220i32).unwrap(),
                tickUpper: alloy::primitives::Signed::try_from(887220i32).unwrap(),
                amount0Desired: U256::from(1_000_000_000_000_000_000u64),
                amount1Desired: U256::from(1_000_000u64),
                amount0Min: U256::ZERO,
                amount1Min: U256::ZERO,
                recipient: Address::ZERO,
                deadline: U256::from(9999999999u64),
            },
        };
        let data = Bytes::from(call.abi_encode());
        match validate_nft_position_calldata(&Some(data)) {
            NftPositionValidation::Allowed(p) => {
                assert_eq!(p.function, "mint");
                assert_eq!(p.token0, Some(WETH));
                assert_eq!(p.token1, Some(USDC));
                assert!(p.token_id.is_none());
            }
            other => panic!("expected Allowed, got {:?}", other),
        }
    }

    #[test]
    fn nft_pm_increase_liquidity_valid() {
        let call = INonfungiblePositionManager::increaseLiquidityCall {
            params: INonfungiblePositionManager::IncreaseLiquidityParams {
                tokenId: U256::from(12345u64),
                amount0Desired: U256::from(1_000_000u64),
                amount1Desired: U256::from(1_000_000u64),
                amount0Min: U256::ZERO,
                amount1Min: U256::ZERO,
                deadline: U256::from(9999999999u64),
            },
        };
        let data = Bytes::from(call.abi_encode());
        match validate_nft_position_calldata(&Some(data)) {
            NftPositionValidation::Allowed(p) => {
                assert_eq!(p.function, "increaseLiquidity");
                assert!(p.token0.is_none());
                assert!(p.token1.is_none());
                assert_eq!(p.token_id, Some(U256::from(12345u64)));
            }
            other => panic!("expected Allowed, got {:?}", other),
        }
    }

    #[test]
    fn nft_pm_decrease_liquidity_valid() {
        let call = INonfungiblePositionManager::decreaseLiquidityCall {
            params: INonfungiblePositionManager::DecreaseLiquidityParams {
                tokenId: U256::from(99u64),
                liquidity: 500_000,
                amount0Min: U256::ZERO,
                amount1Min: U256::ZERO,
                deadline: U256::from(9999999999u64),
            },
        };
        let data = Bytes::from(call.abi_encode());
        match validate_nft_position_calldata(&Some(data)) {
            NftPositionValidation::Allowed(p) => {
                assert_eq!(p.function, "decreaseLiquidity");
                assert_eq!(p.token_id, Some(U256::from(99u64)));
            }
            other => panic!("expected Allowed, got {:?}", other),
        }
    }

    #[test]
    fn nft_pm_collect_valid() {
        let call = INonfungiblePositionManager::collectCall {
            params: INonfungiblePositionManager::CollectParams {
                tokenId: U256::from(42u64),
                recipient: Address::ZERO,
                amount0Max: u128::MAX,
                amount1Max: u128::MAX,
            },
        };
        let data = Bytes::from(call.abi_encode());
        match validate_nft_position_calldata(&Some(data)) {
            NftPositionValidation::Allowed(p) => {
                assert_eq!(p.function, "collect");
                assert_eq!(p.token_id, Some(U256::from(42u64)));
            }
            other => panic!("expected Allowed, got {:?}", other),
        }
    }

    #[test]
    fn nft_pm_burn_valid() {
        let call = INonfungiblePositionManager::burnCall {
            tokenId: U256::from(7u64),
        };
        let data = Bytes::from(call.abi_encode());
        match validate_nft_position_calldata(&Some(data)) {
            NftPositionValidation::Allowed(p) => {
                assert_eq!(p.function, "burn");
                assert_eq!(p.token_id, Some(U256::from(7u64)));
            }
            other => panic!("expected Allowed, got {:?}", other),
        }
    }

    #[test]
    fn nft_pm_no_selector() {
        assert_eq!(
            validate_nft_position_calldata(&None),
            NftPositionValidation::NoSelector
        );
        assert_eq!(
            validate_nft_position_calldata(&Some(Bytes::new())),
            NftPositionValidation::NoSelector
        );
        assert_eq!(
            validate_nft_position_calldata(&Some(Bytes::from(vec![0x88, 0x31, 0x64]))),
            NftPositionValidation::NoSelector
        );
    }

    #[test]
    fn nft_pm_unknown_selector_denied() {
        let data = Bytes::from(vec![0xde, 0xad, 0xbe, 0xef, 0x00, 0x00]);
        assert!(matches!(
            validate_nft_position_calldata(&Some(data)),
            NftPositionValidation::Denied { selector } if selector == [0xde, 0xad, 0xbe, 0xef]
        ));
    }

    #[test]
    fn nft_pm_mint_selector_only_malformed() {
        let data = Bytes::from(vec![0x88, 0x31, 0x64, 0x56]);
        assert!(matches!(
            validate_nft_position_calldata(&Some(data)),
            NftPositionValidation::MalformedArgs { name, .. } if name == "mint"
        ));
    }

    #[test]
    fn nft_pm_increase_selector_only_malformed() {
        let data = Bytes::from(vec![0x21, 0x9f, 0x5d, 0x17]);
        assert!(matches!(
            validate_nft_position_calldata(&Some(data)),
            NftPositionValidation::MalformedArgs { name, .. } if name == "increaseLiquidity"
        ));
    }

    #[test]
    fn nft_pm_decrease_selector_only_malformed() {
        let data = Bytes::from(vec![0x0c, 0x49, 0xcc, 0xbe]);
        assert!(matches!(
            validate_nft_position_calldata(&Some(data)),
            NftPositionValidation::MalformedArgs { name, .. } if name == "decreaseLiquidity"
        ));
    }

    #[test]
    fn nft_pm_collect_selector_only_malformed() {
        let data = Bytes::from(vec![0xfc, 0x6f, 0x78, 0x65]);
        assert!(matches!(
            validate_nft_position_calldata(&Some(data)),
            NftPositionValidation::MalformedArgs { name, .. } if name == "collect"
        ));
    }

    #[test]
    fn nft_pm_burn_selector_only_malformed() {
        let data = Bytes::from(vec![0x42, 0x96, 0x6c, 0x68]);
        assert!(matches!(
            validate_nft_position_calldata(&Some(data)),
            NftPositionValidation::MalformedArgs { name, .. } if name == "burn"
        ));
    }

    #[test]
    fn nft_pm_approve_denied() {
        // approve(address,uint256) is a valid ABI function but not whitelisted
        let call = INonfungiblePositionManager::approveCall {
            to: Address::ZERO,
            tokenId: U256::from(1u64),
        };
        let data = Bytes::from(call.abi_encode());
        assert!(matches!(
            validate_nft_position_calldata(&Some(data)),
            NftPositionValidation::Denied { .. }
        ));
    }

    #[test]
    fn nft_pm_multicall_denied() {
        // multicall(bytes[]) is a valid ABI function but not whitelisted
        let call = INonfungiblePositionManager::multicallCall {
            data: vec![Bytes::from(vec![0x00])],
        };
        let data = Bytes::from(call.abi_encode());
        assert!(matches!(
            validate_nft_position_calldata(&Some(data)),
            NftPositionValidation::Denied { .. }
        ));
    }

    #[test]
    fn nft_pm_transfer_from_denied() {
        // transferFrom is a valid ABI function but not whitelisted
        let call = INonfungiblePositionManager::transferFromCall {
            from: Address::ZERO,
            to: address!("0000000000000000000000000000000000000001"),
            tokenId: U256::from(1u64),
        };
        let data = Bytes::from(call.abi_encode());
        assert!(matches!(
            validate_nft_position_calldata(&Some(data)),
            NftPositionValidation::Denied { .. }
        ));
    }

    #[test]
    fn nft_pm_sweep_token_denied() {
        // sweepToken is a valid ABI function but not whitelisted
        let call = INonfungiblePositionManager::sweepTokenCall {
            token: USDC,
            amountMinimum: U256::from(1u64),
            recipient: Address::ZERO,
        };
        let data = Bytes::from(call.abi_encode());
        assert!(matches!(
            validate_nft_position_calldata(&Some(data)),
            NftPositionValidation::Denied { .. }
        ));
    }

    // ---- ERC-20 validation tests ----

    fn encode_erc20_transfer() -> Bytes {
        let call = IERC20::transferCall {
            _to: USDC,
            _value: U256::from(1_000_000u64),
        };
        Bytes::from(call.abi_encode())
    }

    fn encode_erc20_approve() -> Bytes {
        let call = IERC20::approveCall {
            _spender: USDC,
            _value: U256::MAX,
        };
        Bytes::from(call.abi_encode())
    }

    fn encode_erc20_transfer_from() -> Bytes {
        let call = IERC20::transferFromCall {
            _from: WETH,
            _to: USDC,
            _value: U256::from(5_000u64),
        };
        Bytes::from(call.abi_encode())
    }

    fn encode_erc20_permit() -> Bytes {
        let call = IERC20::permitCall {
            owner: WETH,
            spender: USDC,
            value: U256::from(1_000_000u64),
            deadline: U256::from(9999999999u64),
            v: 27,
            r: alloy::primitives::B256::ZERO,
            s: alloy::primitives::B256::ZERO,
        };
        Bytes::from(call.abi_encode())
    }

    #[test]
    fn erc20_transfer_valid() {
        match validate_erc20_calldata(&Some(encode_erc20_transfer())) {
            Erc20Validation::Allowed(p) => {
                assert_eq!(p.function, "transfer");
                assert_eq!(p.spender_or_recipient, USDC);
                assert_eq!(p.amount, U256::from(1_000_000u64));
                assert!(p.from.is_none());
            }
            other => panic!("expected Allowed, got {:?}", other),
        }
    }

    #[test]
    fn erc20_approve_valid() {
        match validate_erc20_calldata(&Some(encode_erc20_approve())) {
            Erc20Validation::Allowed(p) => {
                assert_eq!(p.function, "approve");
                assert_eq!(p.spender_or_recipient, USDC);
                assert_eq!(p.amount, U256::MAX);
                assert!(p.from.is_none());
            }
            other => panic!("expected Allowed, got {:?}", other),
        }
    }

    #[test]
    fn erc20_transfer_from_valid() {
        match validate_erc20_calldata(&Some(encode_erc20_transfer_from())) {
            Erc20Validation::Allowed(p) => {
                assert_eq!(p.function, "transferFrom");
                assert_eq!(p.spender_or_recipient, USDC);
                assert_eq!(p.amount, U256::from(5_000u64));
                assert_eq!(p.from, Some(WETH));
            }
            other => panic!("expected Allowed, got {:?}", other),
        }
    }

    #[test]
    fn erc20_permit_valid() {
        match validate_erc20_calldata(&Some(encode_erc20_permit())) {
            Erc20Validation::Allowed(p) => {
                assert_eq!(p.function, "permit");
                assert_eq!(p.spender_or_recipient, USDC);
                assert_eq!(p.amount, U256::from(1_000_000u64));
                assert_eq!(p.from, Some(WETH));
            }
            other => panic!("expected Allowed, got {:?}", other),
        }
    }

    #[test]
    fn erc20_no_selector() {
        assert_eq!(validate_erc20_calldata(&None), Erc20Validation::NoSelector);
        assert_eq!(
            validate_erc20_calldata(&Some(Bytes::new())),
            Erc20Validation::NoSelector
        );
        assert_eq!(
            validate_erc20_calldata(&Some(Bytes::from(vec![0xa9, 0x05, 0x9c]))),
            Erc20Validation::NoSelector
        );
    }

    #[test]
    fn erc20_unknown_selector_denied() {
        let data = Bytes::from(vec![0xde, 0xad, 0xbe, 0xef, 0x00, 0x00]);
        assert!(matches!(
            validate_erc20_calldata(&Some(data)),
            Erc20Validation::Denied { selector } if selector == [0xde, 0xad, 0xbe, 0xef]
        ));
    }

    #[test]
    fn erc20_transfer_selector_only_malformed() {
        let data = Bytes::from(vec![0xa9, 0x05, 0x9c, 0xbb]);
        assert!(matches!(
            validate_erc20_calldata(&Some(data)),
            Erc20Validation::MalformedArgs { name, .. } if name == "transfer"
        ));
    }

    #[test]
    fn erc20_approve_selector_only_malformed() {
        let data = Bytes::from(vec![0x09, 0x5e, 0xa7, 0xb3]);
        assert!(matches!(
            validate_erc20_calldata(&Some(data)),
            Erc20Validation::MalformedArgs { name, .. } if name == "approve"
        ));
    }

    #[test]
    fn erc20_transfer_from_selector_only_malformed() {
        let data = Bytes::from(vec![0x23, 0xb8, 0x72, 0xdd]);
        assert!(matches!(
            validate_erc20_calldata(&Some(data)),
            Erc20Validation::MalformedArgs { name, .. } if name == "transferFrom"
        ));
    }

    #[test]
    fn erc20_permit_selector_only_malformed() {
        let data = Bytes::from(vec![0xd5, 0x05, 0xac, 0xcf]);
        assert!(matches!(
            validate_erc20_calldata(&Some(data)),
            Erc20Validation::MalformedArgs { name, .. } if name == "permit"
        ));
    }

    #[test]
    fn erc20_balance_of_denied() {
        // balanceOf is read-only, not allowed via send_raw
        let call = IERC20::balanceOfCall {
            _owner: Address::ZERO,
        };
        let data = Bytes::from(call.abi_encode());
        assert!(matches!(
            validate_erc20_calldata(&Some(data)),
            Erc20Validation::Denied { .. }
        ));
    }

    #[test]
    fn erc20_allowance_denied() {
        // allowance is read-only, not allowed via send_raw
        let call = IERC20::allowanceCall {
            _owner: Address::ZERO,
            _spender: USDC,
        };
        let data = Bytes::from(call.abi_encode());
        assert!(matches!(
            validate_erc20_calldata(&Some(data)),
            Erc20Validation::Denied { .. }
        ));
    }
}
