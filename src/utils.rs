use anyhow::{Context, Result};
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::{
    signature::{Keypair, Signer},
    transaction::Transaction,
    pubkey::Pubkey,
};
use std::sync::Arc;

pub fn load_keypair() -> Result<Keypair> {
    let keypair_path = dirs::home_dir()
        .context("Could not find home directory")?
        .join(".config/solana/id.json");

    let file = std::fs::File::open(&keypair_path)
        .with_context(|| format!("Failed to open keypair file: {:?}", keypair_path))?;
    
    let keypair_bytes: Vec<u8> = serde_json::from_reader(file)
        .context("Failed to parse keypair JSON")?;
    
    let keypair = Keypair::from_bytes(&keypair_bytes)
        .context("Failed to create keypair from bytes")?;

    Ok(keypair)
}

pub async fn fund_account(
    rpc_client: Arc<RpcClient>,
    payer: Arc<Keypair>,
    recipient: &Pubkey,
    amount: u64,
) -> Result<String> {
    log::info!("Funding account {} with {} lamports...", recipient, amount);

    let recent_blockhash = rpc_client.get_latest_blockhash().await?;

    let transaction = Transaction::new_signed_with_payer(
        &[solana_sdk::system_instruction::transfer(
            &payer.pubkey(),
            recipient,
            amount,
        )],
        Some(&payer.pubkey()),
        &[&payer],
        recent_blockhash,
    );

    let fund_signature = rpc_client
        .send_and_confirm_transaction(&transaction)
        .await?;

    log::info!("Fund Transaction Signature: {}", fund_signature);
    Ok(fund_signature.to_string())
}

pub async fn get_sol_balance(
    rpc_client: Arc<RpcClient>,
    account: &Pubkey,
) -> Result<u64> {
    let balance = rpc_client.get_balance(account).await?;
    Ok(balance)
}

pub fn format_token_amount(amount: u64, decimals: u8) -> String {
    let divisor = 10u64.pow(decimals as u32);
    let whole = amount / divisor;
    let fraction = amount % divisor;
    
    if fraction == 0 {
        format!("{}", whole)
    } else {
        format!("{}.{:0width$}", whole, fraction, width = decimals as usize)
            .trim_end_matches('0')
            .trim_end_matches('.')
            .to_string()
    }
}

pub fn parse_token_amount(amount_str: &str, decimals: u8) -> Result<u64> {
    let amount: f64 = amount_str.parse()
        .with_context(|| format!("Invalid amount: {}", amount_str))?;
    
    let multiplier = 10u64.pow(decimals as u32) as f64;
    let result = (amount * multiplier) as u64;
    
    Ok(result)
}

pub fn sol_to_lamports(sol: f64) -> u64 {
    (sol * 1_000_000_000.0) as u64
}

pub fn lamports_to_sol(lamports: u64) -> f64 {
    lamports as f64 / 1_000_000_000.0
}

pub fn validate_pubkey(pubkey_str: &str) -> Result<Pubkey> {
    pubkey_str.parse()
        .with_context(|| format!("Invalid public key: {}", pubkey_str))
}

