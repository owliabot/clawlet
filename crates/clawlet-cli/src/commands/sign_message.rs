//! `clawlet sign-message` — sign a message using EIP-191 personal sign.

use clawlet_rpc::client::RpcClient;

/// Default RPC server address.
const DEFAULT_ADDR: &str = "127.0.0.1:9100";

/// Run the `sign-message` subcommand.
pub async fn run(
    message: String,
    encoding: Option<String>,
    addr: Option<String>,
    auth_token: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let server_addr = addr.as_deref().unwrap_or(DEFAULT_ADDR);

    let client = RpcClient::with_addr(server_addr).with_token(auth_token);
    let resp = client
        .sign_message(&message, encoding.as_deref())
        .await
        .map_err(|e| format!("RPC call failed: {e}"))?;

    println!("✅ Message signed!");
    println!("   Signature: {}", resp.signature);
    println!("   Address:   {}", resp.address);

    Ok(())
}
