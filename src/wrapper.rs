use crate::{
    WrapperConfig, WrapperError, WrapperResult, WrappedTokenInfo, 
    UserConfidentialAccount, TokenClient, Pubkey, Keypair, Signer,
    AeKey, ElGamalKeypair
};
use log::{info, debug};
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::{
    transaction::Transaction,
    program_pack::Pack,
};
use spl_associated_token_account::{
    get_associated_token_address, get_associated_token_address_with_program_id,
    instruction::create_associated_token_account,
};
use spl_token::{
    instruction::transfer,
    state::{Account as TokenAccount, Mint},
};
use spl_token_client::{
    client::{ProgramRpcClient, ProgramRpcClientSendTransaction},
    spl_token_2022::{
        extension::{
            confidential_transfer::{
                instruction::{configure_account, PubkeyValidityProofData},
                account_info::{WithdrawAccountInfo, TransferAccountInfo},
                ConfidentialTransferAccount,
            },
            BaseStateWithExtensions, ExtensionType,
        },
        id as token_2022_program_id,
        instruction::reallocate,
    },
    token::{ExtensionInitializationParams, Token},
};
use spl_token_confidential_transfer_proof_extraction::instruction::{ProofData, ProofLocation};
use spl_token_confidential_transfer_proof_generation::withdraw::WithdrawProofData;
use std::sync::Arc;

// Wrapper for handling confidential token operations
pub struct ConfidentialTokenWrapper {
    pub rpc_client: Arc<RpcClient>,
    pub payer: Arc<Keypair>,
    pub config: WrapperConfig,
    pub wrapper_mint: Keypair,
    pub original_mint: Pubkey,
    pub decimals: u8,
    pub token_client: TokenClient,
}

impl ConfidentialTokenWrapper {
    pub async fn new(
        payer: Arc<Keypair>,
        original_mint: Pubkey,
        config: WrapperConfig,
    ) -> WrapperResult<Self> {
        info!("Creating confidential token wrapper for mint: {}", original_mint);

        let rpc_client = Arc::new(RpcClient::new_with_commitment(
            config.rpc_url.clone(),
            config.commitment,
        ));

        let original_mint_info = rpc_client
            .get_account(&original_mint)
            .await
            .map_err(|_| WrapperError::AccountNotFound(format!("Original mint: {}", original_mint)))?;
        
        let mint_data = Mint::unpack(&original_mint_info.data)
            .map_err(|_| WrapperError::InvalidMint(format!("Failed to unpack mint: {}", original_mint)))?;
        
        let decimals = mint_data.decimals;
        info!("Original mint decimals: {}", decimals);

        let wrapper_mint = {
            use sha2::{Sha256, Digest};
            
            let mut sha_hasher = Sha256::new();
            sha_hasher.update(b"confidential_wrapper_v1");
            sha_hasher.update(original_mint.to_bytes());
            sha_hasher.update(payer.pubkey().to_bytes());
            let seed_hash = sha_hasher.finalize();
            
            let secret_key_bytes: [u8; 32] = seed_hash[..32].try_into()
                .map_err(|_| WrapperError::Other(anyhow::anyhow!("Failed to create secret key")))?;
            
            use ed25519_dalek::{Keypair as Ed25519Keypair};
            let ed25519_keypair = Ed25519Keypair::from_bytes(&{
                let mut full_bytes = [0u8; 64];
                full_bytes[..32].copy_from_slice(&secret_key_bytes);
                
                let secret = ed25519_dalek::SecretKey::from_bytes(&secret_key_bytes)
                    .map_err(|e| WrapperError::Other(anyhow::anyhow!("Invalid secret key: {}", e)))?;
                let public = ed25519_dalek::PublicKey::from(&secret);
                full_bytes[32..].copy_from_slice(public.as_bytes());
                
                full_bytes
            }).map_err(|e| WrapperError::Other(anyhow::anyhow!("Failed to create ed25519 keypair: {}", e)))?;
            
            Keypair::from_bytes(&ed25519_keypair.to_bytes())
                .map_err(|e| WrapperError::Other(anyhow::anyhow!("Failed to create deterministic keypair: {}", e)))?
        };
        
        info!("Generated wrapper mint: {}", wrapper_mint.pubkey());

        let program_client = ProgramRpcClient::new(rpc_client.clone(), ProgramRpcClientSendTransaction);

        let token_client = Token::new(
            Arc::new(program_client),
            &token_2022_program_id(),
            &wrapper_mint.pubkey(),
            Some(decimals),
            payer.clone(),
        );

        Ok(Self {
            rpc_client,
            payer,
            config,
            wrapper_mint,
            original_mint,
            decimals,
            token_client,
        })
    }

    pub async fn initialize(&self) -> WrapperResult<()> {
        info!("Initializing confidential wrapper for mint: {}", self.original_mint);
        info!("Wrapper mint: {}", self.wrapper_mint.pubkey());

        if self.rpc_client.get_account(&self.wrapper_mint.pubkey()).await.is_ok() {
            info!("Wrapper mint already exists, skipping initialization");
            return Ok(());
        }

        let extension_initialization_params =
            vec![ExtensionInitializationParams::ConfidentialTransferMint {
                authority: Some(self.payer.pubkey()),
                auto_approve_new_accounts: self.config.auto_approve_new_accounts,
                auditor_elgamal_pubkey: None,
            }];

        let transaction_signature = self.token_client
            .create_mint(
                &self.payer.pubkey(),
                Some(&self.payer.pubkey()),
                extension_initialization_params,
                &[&self.wrapper_mint],
            )
            .await
            .map_err(|e| WrapperError::TransactionFailed(format!("Failed to create mint: {}", e)))?;

        info!("Wrapper mint created with signature: {}", transaction_signature);
        Ok(())
    }

    pub async fn get_wrapped_token_info(&self) -> WrapperResult<WrappedTokenInfo> {
        let vault_account = self.get_vault_account_address();
        
        let total_wrapped = match self.rpc_client.get_account(&vault_account).await {
            Ok(account_info) => {
                let token_account_data = TokenAccount::unpack(&account_info.data)
                    .map_err(|_| WrapperError::AccountNotFound("Invalid vault account".to_string()))?;
                token_account_data.amount
            }
            Err(_) => 0,
        };

        Ok(WrappedTokenInfo {
            original_mint: self.original_mint,
            wrapper_mint: self.wrapper_mint.pubkey(),
            vault_account,
            decimals: self.decimals,
            total_wrapped,
        })
    }

    pub async fn wrap_tokens(
        &self,
        user: Arc<Keypair>,
        amount: u64,
    ) -> WrapperResult<UserConfidentialAccount> {
        info!("Wrapping {} tokens for user: {}", amount, user.pubkey());

        self.initialize().await?;

        let original_token_account = get_associated_token_address(
            &user.pubkey(),
            &self.original_mint,
        );
        self.verify_user_balance(&original_token_account, amount).await?;

        let vault_account = self.get_or_create_vault_account().await?;
        let confidential_account = self.create_confidential_token_account(user.clone()).await?;

        self.transfer_to_vault(&original_token_account, &vault_account, &user, amount).await?;
        self.mint_confidential_tokens(&confidential_account.account_address, amount).await?;

        self.deposit_to_confidential(&confidential_account.account_address, &user, amount).await?;
        self.apply_pending_balance_for_account(
            &confidential_account.account_address,
            &user,
            &confidential_account.elgamal_keypair,
            &confidential_account.aes_key,
        ).await?;

        info!("Successfully wrapped {} tokens!", amount);
        info!("Confidential token account: {}", confidential_account.account_address);

        Ok(confidential_account)
    }

    pub async fn unwrap_tokens(
        &self,
        user: Arc<Keypair>,
        confidential_account: &UserConfidentialAccount,
        amount: u64,
    ) -> WrapperResult<()> {
        info!("Unwrapping {} confidential tokens for user: {}", amount, user.pubkey());

        self.withdraw_from_confidential(
            &confidential_account.account_address,
            &user,
            &confidential_account.elgamal_keypair,
            &confidential_account.aes_key,
            amount,
        ).await?;

        self.burn_wrapper_tokens(&confidential_account.account_address, &user, amount).await?;

        let user_original_account = get_associated_token_address(
            &user.pubkey(),
            &self.original_mint,
        );
        
        self.ensure_original_token_account_exists(&user, &user_original_account).await?;

        let vault_account = self.get_vault_account_address();
        self.transfer_from_vault(&vault_account, &user_original_account, amount).await?;

        info!("Successfully unwrapped {} tokens!", amount);
        Ok(())
    }



    async fn verify_user_balance(&self, token_account: &Pubkey, required_amount: u64) -> WrapperResult<()> {
        let account_info = self.rpc_client
            .get_account(token_account)
            .await
            .map_err(|_| WrapperError::AccountNotFound(format!("Token account: {}", token_account)))?;
        
        let token_account_data = TokenAccount::unpack(&account_info.data)
            .map_err(|_| WrapperError::InvalidMint("Failed to unpack token account".to_string()))?;
        
        if token_account_data.amount < required_amount {
            return Err(WrapperError::InsufficientBalance {
                required: required_amount,
                available: token_account_data.amount,
            });
        }

        debug!("User balance verified: {} tokens available", token_account_data.amount);
        Ok(())
    }

    async fn get_or_create_vault_account(&self) -> WrapperResult<Pubkey> {
        let vault_account = self.get_vault_account_address();

        if self.rpc_client.get_account(&vault_account).await.is_err() {
            info!("Creating vault account: {}", vault_account);
            
            let create_vault_instruction = create_associated_token_account(
                &self.payer.pubkey(),
                &self.wrapper_mint.pubkey(),
                &self.original_mint,
                &spl_token::id(),
            );

            let recent_blockhash = self.rpc_client
                .get_latest_blockhash()
                .await
                .map_err(WrapperError::SolanaClient)?;
            
            let transaction = Transaction::new_signed_with_payer(
                &[create_vault_instruction],
                Some(&self.payer.pubkey()),
                &[&self.payer],
                recent_blockhash,
            );

            let signature = self.rpc_client
                .send_and_confirm_transaction(&transaction)
                .await
                .map_err(WrapperError::SolanaClient)?;
            
            info!("Vault account created with signature: {}", signature);
        }

        Ok(vault_account)
    }

    fn get_vault_account_address(&self) -> Pubkey {
        get_associated_token_address(&self.wrapper_mint.pubkey(), &self.original_mint)
    }

    async fn create_confidential_token_account(
        &self,
        user: Arc<Keypair>,
    ) -> WrapperResult<UserConfidentialAccount> {
        info!("Creating confidential token account for user: {}", user.pubkey());

        let token_account_pubkey = get_associated_token_address_with_program_id(
            &user.pubkey(),
            &self.wrapper_mint.pubkey(),
            &token_2022_program_id(),
        );

        if self.rpc_client.get_account(&token_account_pubkey).await.is_ok() {
            info!("Confidential token account already exists: {}", token_account_pubkey);
            return UserConfidentialAccount::new(&user, &token_account_pubkey)
                .map_err(WrapperError::Other);
        }

        let create_account_instruction = create_associated_token_account(
            &self.payer.pubkey(),
            &user.pubkey(),
            &self.wrapper_mint.pubkey(),
            &token_2022_program_id(),
        );

        let reallocate_instruction = reallocate(
            &token_2022_program_id(),
            &token_account_pubkey,
            &self.payer.pubkey(),
            &user.pubkey(),
            &[&user.pubkey()],
            &[ExtensionType::ConfidentialTransferAccount],
        ).map_err(|e| WrapperError::TransactionFailed(format!("Reallocate: {}", e)))?;

        let confidential_account = UserConfidentialAccount::new(&user, &token_account_pubkey)
            .map_err(WrapperError::Other)?;

        let maximum_pending_balance_credit_counter = 65536;
        let decryptable_balance = confidential_account.aes_key.encrypt(0);

        let proof_data = PubkeyValidityProofData::new(&confidential_account.elgamal_keypair)
            .map_err(|_| WrapperError::ProofGenerationFailed("PubkeyValidityProofData".to_string()))?;

        let proof_location = ProofLocation::InstructionOffset(
            1.try_into().map_err(|_| WrapperError::Other(anyhow::anyhow!("Invalid proof offset")))?,
            ProofData::InstructionData(&proof_data),
        );

        let configure_account_instructions = configure_account(
            &token_2022_program_id(),
            &token_account_pubkey,
            &self.wrapper_mint.pubkey(),
            &decryptable_balance.into(),
            maximum_pending_balance_credit_counter,
            &user.pubkey(),
            &[],
            proof_location,
        ).map_err(|e| WrapperError::TransactionFailed(format!("Configure account: {}", e)))?;

        let mut instructions = vec![create_account_instruction, reallocate_instruction];
        instructions.extend(configure_account_instructions);

        let recent_blockhash = self.rpc_client
            .get_latest_blockhash()
            .await
            .map_err(WrapperError::SolanaClient)?;
        
        let transaction = Transaction::new_signed_with_payer(
            &instructions,
            Some(&self.payer.pubkey()),
            &[&self.payer],
            recent_blockhash,
        );

        let signature = self.rpc_client
            .send_and_confirm_transaction(&transaction)
            .await
            .map_err(WrapperError::SolanaClient)?;
        
        info!("Confidential token account created with signature: {}", signature);

        Ok(confidential_account)
    }

    async fn transfer_to_vault(
        &self,
        from_account: &Pubkey,
        to_account: &Pubkey,
        user: &Arc<Keypair>,
        amount: u64,
    ) -> WrapperResult<()> {
        debug!("Transferring {} tokens to vault...", amount);

        let transfer_instruction = transfer(
            &spl_token::id(),
            from_account,
            to_account,
            &user.pubkey(),
            &[&user.pubkey()],
            amount,
        ).map_err(|e| WrapperError::TransactionFailed(format!("Transfer instruction: {}", e)))?;

        let recent_blockhash = self.rpc_client
            .get_latest_blockhash()
            .await
            .map_err(WrapperError::SolanaClient)?;
        
        let transaction = Transaction::new_signed_with_payer(
            &[transfer_instruction],
            Some(&self.payer.pubkey()),
            &[&self.payer, user],
            recent_blockhash,
        );

        let signature = self.rpc_client
            .send_and_confirm_transaction(&transaction)
            .await
            .map_err(WrapperError::SolanaClient)?;
        
        debug!("Tokens transferred to vault with signature: {}", signature);
        Ok(())
    }

    async fn mint_confidential_tokens(&self, to_account: &Pubkey, amount: u64) -> WrapperResult<()> {
        debug!("Minting {} confidential tokens...", amount);

        let mint_signature = self.token_client
            .mint_to(
                to_account,
                &self.payer.pubkey(),
                amount,
                &[&self.payer],
            )
            .await
            .map_err(|e| WrapperError::TransactionFailed(format!("Mint tokens: {}", e)))?;

        debug!("Confidential tokens minted with signature: {}", mint_signature);
        Ok(())
    }

    async fn deposit_to_confidential(
        &self,
        token_account: &Pubkey,
        user: &Arc<Keypair>,
        amount: u64,
    ) -> WrapperResult<()> {
        let deposit_signature = self.token_client
            .confidential_transfer_deposit(
                token_account,
                &user.pubkey(),
                amount,
                self.decimals,
                &[user],
            )
            .await
            .map_err(|e| WrapperError::TransactionFailed(format!("Deposit: {}", e)))?;

        debug!("Deposited to confidential with signature: {}", deposit_signature);
        Ok(())
    }

    async fn apply_pending_balance_for_account(
        &self,
        token_account: &Pubkey,
        user: &Arc<Keypair>,
        elgamal_keypair: &ElGamalKeypair,
        aes_key: &AeKey,
    ) -> WrapperResult<()> {
        let apply_signature = self.token_client
            .confidential_transfer_apply_pending_balance(
                token_account,
                &user.pubkey(),
                None,
                elgamal_keypair.secret(),
                aes_key,
                &[user],
            )
            .await
            .map_err(|e| WrapperError::TransactionFailed(format!("Apply pending balance: {}", e)))?;

        debug!("Applied pending balance with signature: {}", apply_signature);
        Ok(())
    }

    //confidential to public balance
    async fn withdraw_from_confidential(
        &self,
        token_account: &Pubkey,
        user: &Arc<Keypair>,
        elgamal_keypair: &ElGamalKeypair,
        aes_key: &AeKey,
        amount: u64,
    ) -> WrapperResult<()> {
        info!("Withdrawing {} tokens from confidential balance...", amount);
        
        let token_account_data = self.token_client
            .get_account_info(token_account)
            .await
            .map_err(|e| WrapperError::AccountNotFound(format!("Token account: {}", e)))?;
        
        let extension_data = token_account_data
            .get_extension::<ConfidentialTransferAccount>()
            .map_err(|e| WrapperError::Other(anyhow::anyhow!("Extension: {}", e)))?;

        let withdraw_account_info = WithdrawAccountInfo::new(extension_data);

        //proof context accounts
        let equality_proof_context_state_keypair = Keypair::new();
        let equality_proof_context_state_pubkey = equality_proof_context_state_keypair.pubkey();
        let range_proof_context_state_keypair = Keypair::new();
        let range_proof_context_state_pubkey = range_proof_context_state_keypair.pubkey();

        let WithdrawProofData {
            equality_proof_data,
            range_proof_data,
        } = withdraw_account_info
            .generate_proof_data(amount, elgamal_keypair, aes_key)
            .map_err(|e| WrapperError::ProofGenerationFailed(format!("Withdraw proof: {}", e)))?;

        info!("Creating equality proof context state account...");
        let equality_proof_signature = self.token_client
            .confidential_transfer_create_context_state_account(
                &equality_proof_context_state_pubkey,
                &self.payer.pubkey(),
                &equality_proof_data,
                false,
                &[&equality_proof_context_state_keypair],
            )
            .await
            .map_err(|e| WrapperError::TransactionFailed(format!("Create equality proof: {}", e)))?;
        
        debug!("Equality proof context created: {}", equality_proof_signature);

        info!("Creating range proof context state account...");
        let range_proof_signature = self.token_client
            .confidential_transfer_create_context_state_account(
                &range_proof_context_state_pubkey,
                &self.payer.pubkey(),
                &range_proof_data,
                true,
                &[&range_proof_context_state_keypair],
            )
            .await
            .map_err(|e| WrapperError::TransactionFailed(format!("Create range proof: {}", e)))?;
        
        debug!("Range proof context created: {}", range_proof_signature);

        info!("Executing withdrawal transaction...");
        let withdraw_signature = self.token_client
            .confidential_transfer_withdraw(
                token_account,
                &user.pubkey(),
                Some(&spl_token_client::token::ProofAccount::ContextAccount(
                    equality_proof_context_state_pubkey,
                )),
                Some(&spl_token_client::token::ProofAccount::ContextAccount(
                    range_proof_context_state_pubkey,
                )),
                amount,
                self.decimals,
                Some(withdraw_account_info),
                elgamal_keypair,
                aes_key,
                &[user],
            )
            .await
            .map_err(|e| WrapperError::TransactionFailed(format!("Withdraw: {}", e)))?;
        
        info!("Withdrawal completed with signature: {}", withdraw_signature);

        info!("Closing proof context state accounts...");

        let close_equality_signature = self.token_client
            .confidential_transfer_close_context_state_account(
                &equality_proof_context_state_pubkey,
                token_account,
                &self.payer.pubkey(),
                &[&self.payer],
            )
            .await
            .map_err(|e| WrapperError::TransactionFailed(format!("Close equality proof: {}", e)))?;
        
        debug!("Closed equality proof: {}", close_equality_signature);

        let close_range_signature = self.token_client
            .confidential_transfer_close_context_state_account(
                &range_proof_context_state_pubkey,
                token_account,
                &self.payer.pubkey(),
                &[&self.payer],
            )
            .await
            .map_err(|e| WrapperError::TransactionFailed(format!("Close range proof: {}", e)))?;
        
        debug!("Closed range proof: {}", close_range_signature);

        info!("Withdrawal completed successfully");
        Ok(())
    }

    async fn burn_wrapper_tokens(
        &self,
        token_account: &Pubkey,
        user: &Arc<Keypair>,
        amount: u64,
    ) -> WrapperResult<()> {
        debug!("Burning {} wrapper tokens...", amount);

        let burn_signature = self.token_client
            .burn(
                token_account,
                &user.pubkey(),
                amount,
                &[user],
            )
            .await
            .map_err(|e| WrapperError::TransactionFailed(format!("Burn: {}", e)))?;

        debug!("Wrapper tokens burned with signature: {}", burn_signature);
        Ok(())
    }

    async fn transfer_from_vault(
        &self,
        from_vault: &Pubkey,
        to_user_account: &Pubkey,
        amount: u64,
    ) -> WrapperResult<()> {
        debug!("Transferring {} tokens from vault to user...", amount);

        let transfer_instruction = transfer(
            &spl_token::id(),
            from_vault,
            to_user_account,
            &self.wrapper_mint.pubkey(),
            &[&self.wrapper_mint.pubkey()],
            amount,
        ).map_err(|e| WrapperError::TransactionFailed(format!("Transfer from vault: {}", e)))?;

        let recent_blockhash = self.rpc_client
            .get_latest_blockhash()
            .await
            .map_err(WrapperError::SolanaClient)?;
        
        let transaction = Transaction::new_signed_with_payer(
            &[transfer_instruction],
            Some(&self.payer.pubkey()),
            &[&self.payer, &self.wrapper_mint],
            recent_blockhash,
        );

        let signature = self.rpc_client
            .send_and_confirm_transaction(&transaction)
            .await
            .map_err(WrapperError::SolanaClient)?;
        
        debug!("Tokens transferred from vault with signature: {}", signature);
        Ok(())
    }

    async fn ensure_original_token_account_exists(
        &self,
        user: &Arc<Keypair>,
        token_account: &Pubkey,
    ) -> WrapperResult<()> {
        if self.rpc_client.get_account(token_account).await.is_err() {
            info!("Creating original token account for user...");
            
            let create_instruction = create_associated_token_account(
                &self.payer.pubkey(),
                &user.pubkey(),
                &self.original_mint,
                &spl_token::id(),
            );

            let recent_blockhash = self.rpc_client
                .get_latest_blockhash()
                .await
                .map_err(WrapperError::SolanaClient)?;
            
            let transaction = Transaction::new_signed_with_payer(
                &[create_instruction],
                Some(&self.payer.pubkey()),
                &[&self.payer],
                recent_blockhash,
            );

            let signature = self.rpc_client
                .send_and_confirm_transaction(&transaction)
                .await
                .map_err(WrapperError::SolanaClient)?;
            
            info!("Original token account created with signature: {}", signature);
        }
        Ok(())
    }
}