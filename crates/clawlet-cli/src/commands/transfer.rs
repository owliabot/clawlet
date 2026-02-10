//! `clawlet transfer` — send ETH or ERC-20 tokens via the running RPC server.
//!
//! Delegates to [`clawlet_rpc::client::RpcClient`] which handles auth,
//! HTTP transport, and JSON-RPC framing.

use clawlet_evm::Address;
use clawlet_rpc::client::RpcClient;
use clawlet_rpc::types::TransferStatus;
use rust_decimal::Decimal;

/// Re-export [`clawlet_rpc::types::TokenSpec`] as `Asset` so the CLI arg
/// type in `main.rs` stays unchanged.
pub type Asset = clawlet_rpc::types::TokenSpec;

/// Default RPC server address.
const DEFAULT_ADDR: &str = "127.0.0.1:9100";

/// Run the `transfer` subcommand.
pub async fn run(
    to: Address,
    amount: Decimal,
    asset: Asset,
    chain_id: Option<u64>,
    addr: Option<String>,
    auth_token: String,
    skip_confirm: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let server_addr = addr.as_deref().unwrap_or(DEFAULT_ADDR);
    let token_spec = asset.to_string();
    let chain_id = chain_id.unwrap_or(1);
    let amount_str = amount.to_string();

    // Show summary and ask for confirmation
    let rpc_url = format!("http://{server_addr}/rpc");
    println!("\n=== Transfer Summary ===");
    println!("  To:       {to}");
    println!("  Amount:   {amount_str} {token_spec}");
    println!("  Chain ID: {chain_id}");
    println!("  Server:   {rpc_url}");
    println!("========================\n");

    if !skip_confirm {
        eprint!("Confirm transfer? [y/N] ");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Transfer cancelled.");
            return Ok(());
        }
    }

    // Use RpcClient for the actual call
    let client = RpcClient::with_addr(server_addr).with_token(auth_token);
    let resp = client
        .transfer(&to.to_string(), &amount_str, &token_spec, chain_id)
        .await
        .map_err(|e| format!("RPC call failed: {e}"))?;

    match resp.status {
        TransferStatus::Success => {
            if let Some(tx_hash) = resp.tx_hash {
                println!("✅ Transaction sent! Hash: {tx_hash}");
            } else {
                println!("✅ Transfer successful.");
            }
            if let Some(audit_id) = &resp.audit_id {
                println!("   Audit ID: {audit_id}");
            }
        }
        TransferStatus::Denied => {
            let reason = resp.reason.as_deref().unwrap_or("no reason given");
            return Err(format!("Transfer denied: {reason}").into());
        }
    }

    Ok(())
}
