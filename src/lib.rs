pub mod wrapper;
pub mod utils;

pub use wrapper::ConfidentialTokenWrapper;
pub use utils::*;

// Common types for external use
pub use solana_sdk::{
    commitment_config::CommitmentConfig,
    signature::{Keypair, Signer},
    pubkey::Pubkey,
};
pub use spl_token_client::{
    client::ProgramRpcClientSendTransaction,
    spl_token_2022::{
        solana_zk_sdk::encryption::{auth_encryption::AeKey, elgamal::{ElGamalKeypair, ElGamalPubkey}},
    },
    token::Token,
};
pub use thiserror::Error;

// Simplified type alias for Token client
pub type TokenClient = Token<ProgramRpcClientSendTransaction>;

// Error types for wrapper operations
#[derive(Error, Debug)]
pub enum WrapperError {
    #[error("Insufficient balance: required {required}, available {available}")]
    InsufficientBalance { required: u64, available: u64 },
    
    #[error("Invalid mint address: {0}")]
    InvalidMint(String),
    
    #[error("Account not found: {0}")]
    AccountNotFound(String),
    
    #[error("Proof generation failed: {0}")]
    ProofGenerationFailed(String),
    
    #[error("Transaction failed: {0}")]
    TransactionFailed(String),
    
    #[error("Solana client error: {0}")]
    SolanaClient(#[from] solana_client::client_error::ClientError),
    
    #[error("SPL Token error: {0}")]
    SplToken(#[from] spl_token::error::TokenError),
    
    #[error("Other error: {0}")]
    Other(#[from] anyhow::Error),
}

pub type WrapperResult<T> = std::result::Result<T, WrapperError>;

// Configuration for the confidential token wrapper
#[derive(Debug, Clone)]
pub struct WrapperConfig {
    pub rpc_url: String,
    pub commitment: CommitmentConfig,
    pub auto_approve_new_accounts: bool,
    pub auditor_elgamal_pubkey: Option<ElGamalPubkey>,
}

impl Default for WrapperConfig {
    fn default() -> Self {
        Self {
            rpc_url: "https://api.devnet.solana.com".to_string(),
            commitment: CommitmentConfig::confirmed(),
            auto_approve_new_accounts: true,
            auditor_elgamal_pubkey: None,
        }
    }
}

// Information about a wrapped token
#[derive(Debug, Clone)]
pub struct WrappedTokenInfo {
    pub original_mint: Pubkey,
    pub wrapper_mint: Pubkey,
    pub vault_account: Pubkey,
    pub decimals: u8,
    pub total_wrapped: u64,
}

// User's confidential token account information
#[derive(Debug, Clone)]
pub struct UserConfidentialAccount {
    pub account_address: Pubkey,
    pub owner: Pubkey,
    pub elgamal_keypair: ElGamalKeypair,
    pub aes_key: AeKey,
}

impl UserConfidentialAccount {
    pub fn new(
        owner: &Keypair,
        account_address: &Pubkey,
    ) -> anyhow::Result<Self> {
        let elgamal_keypair = ElGamalKeypair::new_from_signer(owner, &account_address.to_bytes())
            .map_err(|_| WrapperError::ProofGenerationFailed("Failed to create ElGamal keypair".to_string()))?;
        
        let aes_key = AeKey::new_from_signer(owner, &account_address.to_bytes())
            .map_err(|_| WrapperError::ProofGenerationFailed("Failed to create AES key".to_string()))?;

        Ok(Self {
            account_address: *account_address,
            owner: owner.pubkey(),
            elgamal_keypair,
            aes_key,
        })
    }
}

// Events emitted by the wrapper
#[derive(Debug, Clone)]
pub enum WrapperEvent {
    TokensWrapped {
        user: Pubkey,
        original_mint: Pubkey,
        wrapper_mint: Pubkey,
        amount: u64,
        confidential_account: Pubkey,
    },
    TokensUnwrapped {
        user: Pubkey,
        original_mint: Pubkey,
        wrapper_mint: Pubkey,
        amount: u64,
        confidential_account: Pubkey,
    },
    ConfidentialTransfer {
        from: Pubkey,
        to: Pubkey,
        amount: u64,
        wrapper_mint: Pubkey,
    },
}