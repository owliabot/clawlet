//! Calldata validation for `send_raw` — only allows whitelisted UniswapV3 SwapRouter functions.

use alloy::primitives::Bytes;

/// Allowed UniswapV3 SwapRouter function selectors (first 4 bytes of calldata).
///
/// - `exactInputSingle`:  `0x414bf389`
/// - `exactInput`:        `0xc04b8d59`
/// - `exactOutputSingle`: `0xdb3e2198`
/// - `exactOutput`:       `0xf28c0498`
const ALLOWED_SELECTORS: [[u8; 4]; 4] = [
    [0x41, 0x4b, 0xf3, 0x89], // exactInputSingle
    [0xc0, 0x4b, 0x8d, 0x59], // exactInput
    [0xdb, 0x3e, 0x21, 0x98], // exactOutputSingle
    [0xf2, 0x8c, 0x04, 0x98], // exactOutput
];

/// Human-readable names for the allowed functions (same order as `ALLOWED_SELECTORS`).
const ALLOWED_NAMES: [&str; 4] = [
    "exactInputSingle",
    "exactInput",
    "exactOutputSingle",
    "exactOutput",
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
}

/// Validate that the calldata corresponds to an allowed UniswapV3 SwapRouter function.
pub fn validate_swap_calldata(data: &Option<Bytes>) -> SwapValidation {
    let data = match data {
        Some(d) if d.len() >= 4 => d,
        _ => return SwapValidation::NoSelector,
    };

    let selector: [u8; 4] = [data[0], data[1], data[2], data[3]];

    for (i, allowed) in ALLOWED_SELECTORS.iter().enumerate() {
        if selector == *allowed {
            return SwapValidation::Allowed(ALLOWED_NAMES[i].to_string());
        }
    }

    SwapValidation::Denied { selector }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_input_single_allowed() {
        let data = Bytes::from(vec![0x41, 0x4b, 0xf3, 0x89, 0x00, 0x00]);
        assert!(matches!(
            validate_swap_calldata(&Some(data)),
            SwapValidation::Allowed(name) if name == "exactInputSingle"
        ));
    }

    #[test]
    fn exact_input_allowed() {
        let data = Bytes::from(vec![0xc0, 0x4b, 0x8d, 0x59, 0x00]);
        assert!(matches!(
            validate_swap_calldata(&Some(data)),
            SwapValidation::Allowed(name) if name == "exactInput"
        ));
    }

    #[test]
    fn exact_output_single_allowed() {
        let data = Bytes::from(vec![0xdb, 0x3e, 0x21, 0x98]);
        assert!(matches!(
            validate_swap_calldata(&Some(data)),
            SwapValidation::Allowed(name) if name == "exactOutputSingle"
        ));
    }

    #[test]
    fn exact_output_allowed() {
        let data = Bytes::from(vec![0xf2, 0x8c, 0x04, 0x98, 0xaa]);
        assert!(matches!(
            validate_swap_calldata(&Some(data)),
            SwapValidation::Allowed(name) if name == "exactOutput"
        ));
    }

    #[test]
    fn unknown_selector_denied() {
        let data = Bytes::from(vec![0xde, 0xad, 0xbe, 0xef]);
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
}
