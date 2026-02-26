//! ERC-20 ABI definitions loaded from JSON via alloy's `sol!` macro.

use alloy::sol;

// Load ERC-20 interface from ABI JSON (consistent with other contract ABIs).
sol!(
    #[sol(abi)]
    IERC20,
    "abi/IERC20.json"
);

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{Address, U256};
    use alloy::sol_types::SolCall;

    #[test]
    fn encode_balance_of() {
        let addr = Address::ZERO;
        let call = IERC20::balanceOfCall { _owner: addr };
        let encoded = call.abi_encode();
        // 4 bytes selector + 32 bytes address
        assert_eq!(encoded.len(), 36);
        // balanceOf(address) selector = 0x70a08231
        assert_eq!(&encoded[..4], &[0x70, 0xa0, 0x82, 0x31]);
    }

    #[test]
    fn encode_transfer() {
        let call = IERC20::transferCall {
            _to: Address::ZERO,
            _value: U256::from(1000u64),
        };
        let encoded = call.abi_encode();
        // 4 bytes selector + 32 bytes address + 32 bytes uint256
        assert_eq!(encoded.len(), 68);
        // transfer(address,uint256) selector = 0xa9059cbb
        assert_eq!(&encoded[..4], &[0xa9, 0x05, 0x9c, 0xbb]);
    }

    #[test]
    fn encode_approve() {
        let call = IERC20::approveCall {
            _spender: Address::ZERO,
            _value: U256::MAX,
        };
        let encoded = call.abi_encode();
        assert_eq!(encoded.len(), 68);
        // approve(address,uint256) selector = 0x095ea7b3
        assert_eq!(&encoded[..4], &[0x09, 0x5e, 0xa7, 0xb3]);
    }

    #[test]
    fn encode_transfer_from() {
        let call = IERC20::transferFromCall {
            _from: Address::ZERO,
            _to: Address::with_last_byte(1),
            _value: U256::from(5000u64),
        };
        let encoded = call.abi_encode();
        // 4 bytes selector + 3 * 32 bytes
        assert_eq!(encoded.len(), 100);
        // transferFrom(address,address,uint256) selector = 0x23b872dd
        assert_eq!(&encoded[..4], &[0x23, 0xb8, 0x72, 0xdd]);
    }

    #[test]
    fn encode_permit() {
        let call = IERC20::permitCall {
            owner: Address::ZERO,
            spender: Address::with_last_byte(1),
            value: U256::from(1_000_000u64),
            deadline: U256::from(9999999999u64),
            v: 27,
            r: alloy::primitives::B256::ZERO,
            s: alloy::primitives::B256::ZERO,
        };
        let encoded = call.abi_encode();
        // 4 bytes selector + 7 * 32 bytes
        assert_eq!(encoded.len(), 228);
        // permit(address,address,uint256,uint256,uint8,bytes32,bytes32) selector = 0xd505accf
        assert_eq!(&encoded[..4], &[0xd5, 0x05, 0xac, 0xcf]);
    }

    #[test]
    fn encode_name() {
        let call = IERC20::nameCall {};
        let encoded = call.abi_encode();
        assert_eq!(encoded.len(), 4);
        // name() selector = 0x06fdde03
        assert_eq!(&encoded[..4], &[0x06, 0xfd, 0xde, 0x03]);
    }

    #[test]
    fn encode_decimals() {
        let call = IERC20::decimalsCall {};
        let encoded = call.abi_encode();
        assert_eq!(encoded.len(), 4);
        // decimals() selector = 0x313ce567
        assert_eq!(&encoded[..4], &[0x31, 0x3c, 0xe5, 0x67]);
    }

    #[test]
    fn decode_balance_of_return() {
        // Simulate a return value of 1000
        let mut data = vec![0u8; 32];
        data[31] = 0xe8; // 1000 = 0x3e8
        data[30] = 0x03;
        let decoded: U256 = <IERC20::balanceOfCall as SolCall>::abi_decode_returns(&data).unwrap();
        assert_eq!(decoded, U256::from(1000u64));
    }
}
