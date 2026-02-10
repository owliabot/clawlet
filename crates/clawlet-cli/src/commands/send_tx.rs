//! `clawlet send-tx` — send an arbitrary transaction via the running RPC server.

use alloy::primitives::{Address, Bytes};
use clawlet_rpc::client::RpcClient;
use clawlet_rpc::types::SendTxStatus;
use rust_decimal::Decimal;

/// Default RPC server address.
const DEFAULT_ADDR: &str = "127.0.0.1:9100";

/// Run the `send-tx` subcommand.
pub async fn run(
    to: Address,
    value: Option<Decimal>,
    data: Option<Bytes>,
    chain_id: Option<u64>,
    gas_limit: Option<u64>,
    addr: Option<String>,
    auth_token: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let server_addr = addr.as_deref().unwrap_or(DEFAULT_ADDR);
    let rpc_url = format!("http://{server_addr}/rpc");

    println!("\n=== Send Transaction ===");
    println!("  To:       {to}");
    if let Some(v) = value {
        println!("  Value:    {v} ETH");
    }
    if let Some(ref d) = data {
        println!("  Data:     {d}");
    }
    println!("  Chain ID: {}", chain_id.unwrap_or(1));
    if let Some(g) = gas_limit {
        println!("  Gas Limit: {g}");
    }
    println!("  Server:   {rpc_url}");
    println!("========================\n");

    let client = RpcClient::with_addr(server_addr).with_token(auth_token);
    let resp = client
        .send_transaction(to, value, data, chain_id, gas_limit)
        .await
        .map_err(|e| format!("RPC call failed: {e}"))?;

    match resp.status {
        SendTxStatus::Success => {
            if let Some(tx_hash) = resp.tx_hash {
                println!("✅ Transaction sent! Hash: {tx_hash}");
            } else {
                println!("✅ Transaction successful.");
            }
            if let Some(audit_id) = &resp.audit_id {
                println!("   Audit ID: {audit_id}");
            }
        }
        SendTxStatus::Denied => {
            let reason = resp.reason.as_deref().unwrap_or("no reason given");
            return Err(format!("Transaction denied: {reason}").into());
        }
    }

    Ok(())
}
