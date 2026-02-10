//! `clawlet send-tx` — send an arbitrary transaction via the running RPC server.

use clawlet_rpc::client::RpcClient;
use clawlet_rpc::types::SendTxStatus;

/// Default RPC server address.
const DEFAULT_ADDR: &str = "127.0.0.1:9100";

/// Run the `send-tx` subcommand.
pub async fn run(
    to: String,
    value: Option<String>,
    data: Option<String>,
    chain_id: Option<u64>,
    gas_limit: Option<String>,
    addr: Option<String>,
    auth_token: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let server_addr = addr.as_deref().unwrap_or(DEFAULT_ADDR);
    let rpc_url = format!("http://{server_addr}/rpc");

    println!("\n=== Send Transaction ===");
    println!("  To:       {to}");
    if let Some(ref v) = value {
        println!("  Value:    {v} ETH");
    }
    if let Some(ref d) = data {
        println!("  Data:     {d}");
    }
    println!("  Chain ID: {}", chain_id.unwrap_or(1));
    if let Some(ref g) = gas_limit {
        println!("  Gas Limit: {g}");
    }
    println!("  Server:   {rpc_url}");
    println!("========================\n");

    let client = RpcClient::with_addr(server_addr).with_token(auth_token);
    let resp = client
        .send_transaction(
            &to,
            value.as_deref(),
            data.as_deref(),
            chain_id,
            gas_limit.as_deref(),
        )
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
