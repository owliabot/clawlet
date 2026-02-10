//! `clawlet transfer` — send ETH or ERC-20 tokens via the running RPC server.
//!
//! Builds a JSON-RPC request and POSTs it to the clawlet server.
//! All keystore unlocking, policy checking, signing, and broadcasting
//! happen server-side.

use clawlet_evm::Address;
use rust_decimal::Decimal;
use serde_json::json;

/// Default RPC server address.
const DEFAULT_ADDR: &str = "127.0.0.1:9100";

/// Run the `transfer` subcommand.
pub async fn run(
    to: Address,
    amount: Decimal,
    asset: String,
    chain_id: Option<u64>,
    addr: Option<String>,
    auth_token: String,
    skip_confirm: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let server_addr = addr.as_deref().unwrap_or(DEFAULT_ADDR);
    let rpc_url = format!("http://{server_addr}/rpc");

    // Build the token spec: "ETH" for native, or the contract address as-is
    let token_spec = if asset.eq_ignore_ascii_case("ETH") {
        "ETH".to_string()
    } else {
        asset.clone()
    };

    // Resolve chain_id (default to 1 if not specified)
    let chain_id = chain_id.unwrap_or(1);

    // Convert human-readable amount to string for the RPC call
    let amount_str = amount.to_string();

    // Show summary and ask for confirmation
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

    // Build JSON-RPC request
    // Server expects `token_type` field (not `token`) per TransferRequestWithAuth
    let request_body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "transfer",
        "params": {
            "to": to.to_string(),
            "amount": amount_str,
            "token_type": token_spec,
            "chain_id": chain_id,
        }
    });

    // Send request
    let client = reqwest::Client::new();
    let response = client
        .post(&rpc_url)
        .header("Authorization", format!("Bearer {auth_token}"))
        .header("Content-Type", "application/json")
        .json(&request_body)
        .send()
        .await
        .map_err(|e| format!("failed to connect to clawlet server at {rpc_url}: {e}"))?;

    let status = response.status();
    let body: serde_json::Value = response
        .json()
        .await
        .map_err(|e| format!("failed to parse server response: {e}"))?;

    // Handle JSON-RPC error
    if let Some(error) = body.get("error") {
        let message = error
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown error");
        let code = error.get("code").and_then(|c| c.as_i64()).unwrap_or(0);
        return Err(format!("RPC error {code}: {message}").into());
    }

    if !status.is_success() {
        return Err(format!("HTTP {status}: {body}").into());
    }

    // Extract result
    let result = body
        .get("result")
        .ok_or("missing 'result' field in response")?;

    let tx_status = result
        .get("status")
        .and_then(|s| s.as_str())
        .unwrap_or("unknown");

    match tx_status {
        "success" => {
            if let Some(tx_hash) = result.get("tx_hash").and_then(|h| h.as_str()) {
                println!("✅ Transaction sent! Hash: {tx_hash}");
            } else {
                println!("✅ Transfer successful: {result}");
            }
            if let Some(audit_id) = result.get("audit_id").and_then(|a| a.as_str()) {
                println!("   Audit ID: {audit_id}");
            }
        }
        "denied" => {
            let reason = result
                .get("reason")
                .and_then(|r| r.as_str())
                .unwrap_or("no reason given");
            return Err(format!("Transfer denied: {reason}").into());
        }
        _ => {
            println!("Transfer result: {result}");
        }
    }

    Ok(())
}
