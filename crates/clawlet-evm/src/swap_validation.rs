//! Calldata validation for `send_raw` — only allows whitelisted UniswapV3 SwapRouter functions
//! targeting known router contract addresses.

use alloy::primitives::{address, Address, Bytes};

/// Canonical UniswapV3 SwapRouter address, shared across all supported chains:
/// `0xE592427A0AEce92De3Edee1F18E0157C05861564`
///
/// Supported chains: 1 (Ethereum), 10 (Optimism), 56 (BNB), 137 (Polygon),
/// 8453 (Base), 42161 (Arbitrum).
const CANONICAL_SWAP_ROUTER: Address = address!("E592427A0AEce92De3Edee1F18E0157C05861564");

/// Returns `true` if `to` is a known UniswapV3 SwapRouter for the given chain.
///
/// Only explicitly listed chains are allowed. Unknown chains are rejected.
pub fn is_allowed_router(to: Address, chain_id: u64) -> bool {
    match chain_id {
        // Ethereum mainnet
        1 => to == CANONICAL_SWAP_ROUTER,
        // Optimism
        10 => to == CANONICAL_SWAP_ROUTER,
        // Polygon
        137 => to == CANONICAL_SWAP_ROUTER,
        // Arbitrum
        42161 => to == CANONICAL_SWAP_ROUTER,
        // Base
        8453 => to == CANONICAL_SWAP_ROUTER,
        // BNB Chain
        56 => to == CANONICAL_SWAP_ROUTER,
        // Unknown chain — deny
        _ => false,
    }
}

/// Allowed UniswapV3 SwapRouter function selectors (first 4 bytes of calldata).
///
/// - `exactInputSingle`:  `0x414bf389`  — expects 8×32 = 256 bytes of args
/// - `exactInput`:        `0xc04b8d59`  — expects ≥ 5×32 = 160 bytes (dynamic `bytes path`)
/// - `exactOutputSingle`: `0xdb3e2198`  — expects 8×32 = 256 bytes of args
/// - `exactOutput`:       `0xf28c0498`  — expects ≥ 5×32 = 160 bytes (dynamic `bytes path`)
struct AllowedSelector {
    selector: [u8; 4],
    name: &'static str,
    /// Minimum calldata length (selector + args).
    min_len: usize,
}

const ALLOWED: [AllowedSelector; 4] = [
    AllowedSelector {
        selector: [0x41, 0x4b, 0xf3, 0x89],
        name: "exactInputSingle",
        min_len: 4 + 256, // 8 static tuple fields × 32
    },
    AllowedSelector {
        selector: [0xc0, 0x4b, 0x8d, 0x59],
        name: "exactInput",
        min_len: 4 + 160, // 5 fields (dynamic path needs ≥ 160)
    },
    AllowedSelector {
        selector: [0xdb, 0x3e, 0x21, 0x98],
        name: "exactOutputSingle",
        min_len: 4 + 256,
    },
    AllowedSelector {
        selector: [0xf2, 0x8c, 0x04, 0x98],
        name: "exactOutput",
        min_len: 4 + 160,
    },
];

/// Result of validating raw transaction calldata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SwapValidation {
    /// The calldata matches an allowed UniswapV3 swap function.
    Allowed(String),
    /// The calldata is missing or too short to contain a function selector.
    NoSelector,
    /// The function selector is not in the whitelist.
    Denied { selector: [u8; 4] },
    /// The function selector is correct but the calldata is too short (malformed).
    MalformedArgs {
        name: String,
        expected_min: usize,
        actual: usize,
    },
}

/// Validate that the calldata corresponds to an allowed UniswapV3 SwapRouter function
/// and has sufficient length for ABI-encoded arguments.
pub fn validate_swap_calldata(data: &Option<Bytes>) -> SwapValidation {
    let data = match data {
        Some(d) if d.len() >= 4 => d,
        _ => return SwapValidation::NoSelector,
    };

    let selector: [u8; 4] = [data[0], data[1], data[2], data[3]];

    for entry in &ALLOWED {
        if selector == entry.selector {
            if data.len() < entry.min_len {
                return SwapValidation::MalformedArgs {
                    name: entry.name.to_string(),
                    expected_min: entry.min_len,
                    actual: data.len(),
                };
            }
            return SwapValidation::Allowed(entry.name.to_string());
        }
    }

    SwapValidation::Denied { selector }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Router address tests ----

    #[test]
    fn canonical_router_allowed_on_mainnet() {
        assert!(is_allowed_router(CANONICAL_SWAP_ROUTER, 1));
    }

    #[test]
    fn canonical_router_allowed_on_base() {
        assert!(is_allowed_router(CANONICAL_SWAP_ROUTER, 8453));
    }

    #[test]
    fn canonical_router_allowed_on_bnb() {
        assert!(is_allowed_router(CANONICAL_SWAP_ROUTER, 56));
    }

    #[test]
    fn random_address_denied() {
        let random = address!("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
        assert!(!is_allowed_router(random, 1));
        assert!(!is_allowed_router(random, 56));
    }

    #[test]
    fn unknown_chain_denied() {
        // Even canonical router is denied on unlisted chains
        assert!(!is_allowed_router(CANONICAL_SWAP_ROUTER, 999));
        assert!(!is_allowed_router(CANONICAL_SWAP_ROUTER, 43114)); // Avalanche not listed
    }

    #[test]
    fn all_listed_chains_accept_canonical() {
        for chain in [1, 10, 137, 42161, 8453, 56] {
            assert!(
                is_allowed_router(CANONICAL_SWAP_ROUTER, chain),
                "canonical router should be allowed on chain {chain}"
            );
        }
    }

    // ---- Selector tests ----

    fn make_data(selector: [u8; 4], extra_len: usize) -> Bytes {
        let mut v = selector.to_vec();
        v.extend(vec![0u8; extra_len]);
        Bytes::from(v)
    }

    #[test]
    fn exact_input_single_allowed() {
        let data = make_data([0x41, 0x4b, 0xf3, 0x89], 256);
        assert!(matches!(
            validate_swap_calldata(&Some(data)),
            SwapValidation::Allowed(name) if name == "exactInputSingle"
        ));
    }

    #[test]
    fn exact_input_allowed() {
        let data = make_data([0xc0, 0x4b, 0x8d, 0x59], 160);
        assert!(matches!(
            validate_swap_calldata(&Some(data)),
            SwapValidation::Allowed(name) if name == "exactInput"
        ));
    }

    #[test]
    fn exact_output_single_allowed() {
        let data = make_data([0xdb, 0x3e, 0x21, 0x98], 256);
        assert!(matches!(
            validate_swap_calldata(&Some(data)),
            SwapValidation::Allowed(name) if name == "exactOutputSingle"
        ));
    }

    #[test]
    fn exact_output_allowed() {
        let data = make_data([0xf2, 0x8c, 0x04, 0x98], 160);
        assert!(matches!(
            validate_swap_calldata(&Some(data)),
            SwapValidation::Allowed(name) if name == "exactOutput"
        ));
    }

    #[test]
    fn unknown_selector_denied() {
        let data = make_data([0xde, 0xad, 0xbe, 0xef], 256);
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

    // ---- Malformed args tests ----

    #[test]
    fn exact_input_single_too_short() {
        // selector + only 100 bytes (needs 256)
        let data = make_data([0x41, 0x4b, 0xf3, 0x89], 100);
        assert!(matches!(
            validate_swap_calldata(&Some(data)),
            SwapValidation::MalformedArgs { name, expected_min: 260, actual: 104 } if name == "exactInputSingle"
        ));
    }

    #[test]
    fn exact_input_too_short() {
        // selector + only 32 bytes (needs 160)
        let data = make_data([0xc0, 0x4b, 0x8d, 0x59], 32);
        assert!(matches!(
            validate_swap_calldata(&Some(data)),
            SwapValidation::MalformedArgs { name, expected_min: 164, actual: 36 } if name == "exactInput"
        ));
    }

    #[test]
    fn selector_only_is_malformed() {
        // Just 4 bytes, no args
        let data = Bytes::from(vec![0x41, 0x4b, 0xf3, 0x89]);
        assert!(matches!(
            validate_swap_calldata(&Some(data)),
            SwapValidation::MalformedArgs { .. }
        ));
    }
}
