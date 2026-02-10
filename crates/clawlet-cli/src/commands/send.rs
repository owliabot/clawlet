//! `clawlet send` — send a raw transaction via the running RPC server (bypasses policy engine).

use alloy::primitives::{Address, U256};
use clawlet_rpc::client::RpcClient;

/// Default RPC server address.
const DEFAULT_ADDR: &str = "127.0.0.1:9100";

/// Run the `send` subcommand.
pub async fn run(
    to: Address,
    value: Option<U256>,
    data: Option<String>,
    chain_id: Option<u64>,
    gas_limit: Option<u64>,
    addr: Option<String>,
    auth_token: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let server_addr = addr.as_deref().unwrap_or(DEFAULT_ADDR);
    let chain_id = chain_id.unwrap_or(1);

    let rpc_url = format!("http://{server_addr}/rpc");
    println!("\n=== Raw Send Summary ===");
    println!("  To:       {to}");
    println!(
        "  Value:    {} ETH",
        value.map_or_else(|| "0".to_string(), |v| v.to_string())
    );
    if let Some(ref d) = data {
        println!("  Data:     {d}");
    }
    println!("  Chain ID: {chain_id}");
    if let Some(gl) = gas_limit {
        println!("  Gas Limit: {gl}");
    }
    println!("  Server:   {rpc_url}");
    println!("=========================\n");

    let client = RpcClient::with_addr(server_addr).with_token(auth_token);
    let resp = client
        .send_raw(to, value, data.as_deref(), chain_id, gas_limit)
        .await
        .map_err(|e| format!("RPC call failed: {e}"))?;

    println!("✅ Transaction sent! Hash: {}", resp.tx_hash);
    println!("   Audit ID: {}", resp.audit_id);

    Ok(())
}
