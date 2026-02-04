//! ERC-20 ABI definitions using alloy's `sol!` macro.

use alloy::sol;

sol! {
    /// ERC-20 token interface.
    #[sol(rpc)]
    interface IERC20 {
        function balanceOf(address owner) external view returns (uint256);
        function transfer(address to, uint256 amount) external returns (bool);
        function approve(address spender, uint256 amount) external returns (bool);
        function allowance(address owner, address spender) external view returns (uint256);
        function name() external view returns (string);
        function symbol() external view returns (string);
        function decimals() external view returns (uint8);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{Address, U256};
    use alloy::sol_types::SolCall;

    #[test]
    fn encode_balance_of() {
        let addr = Address::ZERO;
        let call = IERC20::balanceOfCall { owner: addr };
        let encoded = call.abi_encode();
        // 4 bytes selector + 32 bytes address
        assert_eq!(encoded.len(), 36);
        // balanceOf(address) selector = 0x70a08231
        assert_eq!(&encoded[..4], &[0x70, 0xa0, 0x82, 0x31]);
    }

    #[test]
    fn encode_transfer() {
        let to = Address::ZERO;
        let amount = U256::from(1000u64);
        let call = IERC20::transferCall { to, amount };
        let encoded = call.abi_encode();
        // 4 bytes selector + 32 bytes address + 32 bytes uint256
        assert_eq!(encoded.len(), 68);
        // transfer(address,uint256) selector = 0xa9059cbb
        assert_eq!(&encoded[..4], &[0xa9, 0x05, 0x9c, 0xbb]);
    }

    #[test]
    fn encode_approve() {
        let spender = Address::ZERO;
        let amount = U256::MAX;
        let call = IERC20::approveCall { spender, amount };
        let encoded = call.abi_encode();
        assert_eq!(encoded.len(), 68);
        // approve(address,uint256) selector = 0x095ea7b3
        assert_eq!(&encoded[..4], &[0x09, 0x5e, 0xa7, 0xb3]);
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
