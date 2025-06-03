use anyhow::Result;
use clap::{Parser, Subcommand};
use confidential_transfer_wrapper::{
    ConfidentialTokenWrapper, WrapperConfig, UserConfidentialAccount,
    load_keypair, fund_account, get_sol_balance,
    format_token_amount, parse_token_amount, validate_pubkey,
    sol_to_lamports, lamports_to_sol,
    Pubkey, Keypair,
};
use log::{info, warn};
use solana_sdk::signature::Signer;
use std::sync::Arc;

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    
    #[arg(long, default_value = "https://api.devnet.solana.com")]
    rpc_url: String,
    
    #[arg(long)]
    keypair_path: Option<String>,
    
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    Init {
        #[arg(long)]
        mint: String,
    },
    
    Wrap {
        #[arg(long)]
        mint: String,
        
        #[arg(long)]
        amount: String,
        
        #[arg(long)]
        user_address: Option<String>,
    },
    
    Unwrap {
        #[arg(long)]
        mint: String,
        
        #[arg(long)]
        amount: String,
        
        #[arg(long)]
        confidential_account: String,
    },
    
    Info {
        #[arg(long)]
        mint: String,
    },
    
    Fund {
        #[arg(long)]
        account: String,
        
        #[arg(long, default_value = "1.0")]
        amount: f64,
    },
    
    Balance {
        #[arg(long)]
        account: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    
    let log_level = if cli.verbose { "debug" } else { "info" };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(log_level)).init();
    
    let payer = Arc::new(if let Some(path) = cli.keypair_path {
        load_keypair_from_path(&path)?
    } else {
        load_keypair()?
    });
    
    info!("Payer: {}", payer.pubkey());
    info!("RPC URL: {}", cli.rpc_url);
    
    let config = WrapperConfig {
        rpc_url: cli.rpc_url,
        ..Default::default()
    };
    
    match cli.command {
        Commands::Init { mint } => {
            let mint_pubkey = validate_pubkey(&mint)?;
            init_wrapper(payer, mint_pubkey, config).await?;
        }
        
        Commands::Wrap { mint, amount, user_address } => {
            let mint_pubkey = validate_pubkey(&mint)?;
            
            let _user_pubkey = if let Some(addr) = user_address {
                validate_pubkey(&addr)?
            } else {
                payer.pubkey()
            };
            
            wrap_tokens(payer.clone(), mint_pubkey, payer.clone(), &amount, config).await?;
        }
        
        Commands::Unwrap { mint, amount, confidential_account } => {
            let mint_pubkey = validate_pubkey(&mint)?;
            let confidential_account_pubkey = validate_pubkey(&confidential_account)?;
            
            unwrap_tokens(payer.clone(), mint_pubkey, payer.clone(), &amount, confidential_account_pubkey, config).await?;
        }
        
        Commands::Info { mint } => {
            let mint_pubkey = validate_pubkey(&mint)?;
            show_wrapper_info(payer, mint_pubkey, config).await?;
        }
        
        Commands::Fund { account, amount } => {
            let account_pubkey = validate_pubkey(&account)?;
            fund_account_cmd(payer, account_pubkey, amount, config).await?;
        }
        
        Commands::Balance { account } => {
            let account_pubkey = validate_pubkey(&account)?;
            check_balance(account_pubkey, config).await?;
        }
    }
    
    Ok(())
}

async fn init_wrapper(
    payer: Arc<Keypair>,
    mint: Pubkey,
    config: WrapperConfig,
) -> Result<()> {
    info!("Initializing wrapper for mint: {}", mint);
    
    let wrapper = ConfidentialTokenWrapper::new(payer, mint, config).await?;
    wrapper.initialize().await?;
    
    let info = wrapper.get_wrapped_token_info().await?;
    
    println!("Wrapper initialized successfully!");
    println!("Wrapper Details:");
    println!("   Original Mint: {}", info.original_mint);
    println!("   Wrapper Mint:  {}", info.wrapper_mint);
    println!("   Vault Account: {}", info.vault_account);
    println!("   Decimals:      {}", info.decimals);
    println!("   Total Wrapped: {}", format_token_amount(info.total_wrapped, info.decimals));
    
    Ok(())
}

async fn wrap_tokens(
    payer: Arc<Keypair>,
    mint: Pubkey,
    user: Arc<Keypair>,
    amount_str: &str,
    config: WrapperConfig,
) -> Result<()> {
    info!("Wrapping tokens for user: {}", user.pubkey());
    
    let wrapper = ConfidentialTokenWrapper::new(payer.clone(), mint, config.clone()).await?;
    
    let info = wrapper.get_wrapped_token_info().await?;
    let amount = parse_token_amount(amount_str, info.decimals)?;
    
    let rpc_client = Arc::new(solana_client::nonblocking::rpc_client::RpcClient::new_with_commitment(
        config.rpc_url.clone(),
        config.commitment,
    ));
    
    let user_balance = get_sol_balance(rpc_client.clone(), &user.pubkey()).await?;
    if user_balance < sol_to_lamports(0.01) {
        warn!("User has low SOL balance, funding account...");
        fund_account(rpc_client, payer.clone(), &user.pubkey(), sol_to_lamports(0.1)).await?;
    }
    
    let confidential_account = wrapper.wrap_tokens(user.clone(), amount).await?;
    
    println!("Tokens wrapped successfully!");
    println!("Wrap Details:");
    println!("   User:                {}", user.pubkey());
    println!("   Amount Wrapped:      {}", format_token_amount(amount, info.decimals));
    println!("   Confidential Account: {}", confidential_account.account_address);
    println!("   ElGamal Pubkey:      {}", confidential_account.elgamal_keypair.pubkey());
    
    save_user_data(&user, &confidential_account, &mint)?;
    
    Ok(())
}

async fn unwrap_tokens(
    payer: Arc<Keypair>,
    mint: Pubkey,
    user: Arc<Keypair>,
    amount_str: &str,
    confidential_account_pubkey: Pubkey,
    config: WrapperConfig,
) -> Result<()> {
    info!("Unwrapping tokens for user: {}", user.pubkey());
    
    let wrapper = ConfidentialTokenWrapper::new(payer, mint, config).await?;
    
    let info = wrapper.get_wrapped_token_info().await?;
    let amount = parse_token_amount(amount_str, info.decimals)?;
    
    let confidential_account = UserConfidentialAccount::new(&user, &confidential_account_pubkey)?;
    
    wrapper.unwrap_tokens(user.clone(), &confidential_account, amount).await?;
    
    println!("Tokens unwrapped successfully!");
    println!("Unwrap Details:");
    println!("   User:             {}", user.pubkey());
    println!("   Amount Unwrapped: {}", format_token_amount(amount, info.decimals));
    println!("   From Account:     {}", confidential_account_pubkey);
    
    Ok(())
}

async fn show_wrapper_info(
    payer: Arc<Keypair>,
    mint: Pubkey,
    config: WrapperConfig,
) -> Result<()> {
    let wrapper = ConfidentialTokenWrapper::new(payer, mint, config).await?;
    let info = wrapper.get_wrapped_token_info().await?;
    
    println!("Wrapper Information:");
    println!("   Original Mint:    {}", info.original_mint);
    println!("   Wrapper Mint:     {}", info.wrapper_mint);
    println!("   Vault Account:    {}", info.vault_account);
    println!("   Decimals:         {}", info.decimals);
    println!("   Total Wrapped:    {}", format_token_amount(info.total_wrapped, info.decimals));
    
    Ok(())
}

async fn fund_account_cmd(
    payer: Arc<Keypair>,
    account: Pubkey,
    amount: f64,
    config: WrapperConfig,
) -> Result<()> {
    let rpc_client = Arc::new(solana_client::nonblocking::rpc_client::RpcClient::new_with_commitment(
        config.rpc_url,
        config.commitment,
    ));
    
    let lamports = sol_to_lamports(amount);
    let signature = fund_account(rpc_client, payer, &account, lamports).await?;
    
    println!("Account funded!");
    println!("   Account:   {}", account);
    println!("   Amount:    {} SOL", amount);
    println!("   Signature: {}", signature);
    
    Ok(())
}

async fn check_balance(
    account: Pubkey,
    config: WrapperConfig,
) -> Result<()> {
    let rpc_client = Arc::new(solana_client::nonblocking::rpc_client::RpcClient::new_with_commitment(
        config.rpc_url,
        config.commitment,
    ));
    
    let balance = get_sol_balance(rpc_client, &account).await?;
    
    println!("Account Balance:");
    println!("   Account: {}", account);
    println!("   Balance: {} SOL ({} lamports)", lamports_to_sol(balance), balance);
    
    Ok(())
}

fn load_keypair_from_path(path: &str) -> Result<Keypair> {
    let file = std::fs::File::open(path)?;
    let keypair_bytes: Vec<u8> = serde_json::from_reader(file)?;
    let keypair = Keypair::from_bytes(&keypair_bytes)?;
    Ok(keypair)
}

fn save_user_data(
    user: &Keypair,
    confidential_account: &UserConfidentialAccount,
    mint: &Pubkey,
) -> Result<()> {
    let user_data = serde_json::json!({
        "user_pubkey": user.pubkey().to_string(),
        "confidential_account": confidential_account.account_address.to_string(),
        "elgamal_pubkey": confidential_account.elgamal_keypair.pubkey().to_string(),
        "mint": mint.to_string(),
        "created_at": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    });
    
    let filename = format!("user-data-{}.json", &user.pubkey().to_string()[..8]);
    std::fs::write(&filename, serde_json::to_string_pretty(&user_data)?)?;
    
    println!("User data saved to: {}", filename);
    Ok(())
}