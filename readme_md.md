# Confidential Token Wrapper

A Rust CLI tool for wrapping any SPL token into confidential tokens using Solana's Token-2022 program with confidential transfer extensions.

## Overview

This wrapper allows you to:
- Take any existing SPL token and wrap it into a confidential version
- Transfer the confidential tokens privately (amounts are encrypted)
- Unwrap confidential tokens back to the original SPL tokens

## Prerequisites

- Rust toolchain installed
- Solana CLI installed and configured
- A Solana wallet with SOL for transaction fees
- Access to Solana devnet/mainnet

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd confidential-transfer
```

2. Build the project:
```bash
cargo build --release
```

## Configuration

The CLI uses your default Solana wallet located at `~/.config/solana/id.json`. Make sure you have:
- A configured Solana wallet
- Sufficient SOL for transaction fees
- Some SPL tokens to wrap (for testing)

## Usage

### 1. Initialize Wrapper

Create a confidential wrapper for any SPL token:
```bash
cargo run --bin wrapper_example -- init --mint <SPL_TOKEN_MINT_ADDRESS>
```

Example:
```bash
cargo run --bin wrapper_example -- init --mint ApxaHZoparjZFytE7Cxkp8meSybtmpXvgPjBzUpLdtki
```

### 2. Wrap Tokens

Convert SPL tokens to confidential tokens:
```bash
cargo run --bin wrapper_example -- wrap --mint <SPL_TOKEN_MINT_ADDRESS> --amount <AMOUNT>
```

Example:
```bash
cargo run --bin wrapper_example -- wrap --mint ApxaHZoparjZFytE7Cxkp8meSybtmpXvgPjBzUpLdtki --amount 10
```

### 3. Check Wrapper Information

View details about the wrapper:
```bash
cargo run --bin wrapper_example -- info --mint <SPL_TOKEN_MINT_ADDRESS>
```

### 4. Unwrap Tokens

Convert confidential tokens back to SPL tokens:
```bash
cargo run --bin wrapper_example -- unwrap --mint <SPL_TOKEN_MINT_ADDRESS> --amount <AMOUNT> --confidential-account <CONFIDENTIAL_ACCOUNT_ADDRESS>
```

Example:
```bash
cargo run --bin wrapper_example -- unwrap --mint ApxaHZoparjZFytE7Cxkp8meSybtmpXvgPjBzUpLdtki --amount 5 --confidential-account 75ZupPZEyuU1vsZDkTjp1Lpfmh5ySZAodBfv5Viu3uCU
```

### 5. Utility Commands

Check account balance:
```bash
cargo run --bin wrapper_example -- balance --account <ACCOUNT_ADDRESS>
```

Fund an account with SOL:
```bash
cargo run --bin wrapper_example -- fund --account <ACCOUNT_ADDRESS> --amount 1.0
```

## How It Works

### Wrapping Process
1. User deposits original SPL tokens into a secure vault
2. Equivalent confidential wrapper tokens are minted using Token-2022
3. Tokens are moved to confidential balance using encryption
4. User receives confidential tokens with encrypted amounts

### Unwrapping Process
1. Confidential tokens are withdrawn from encrypted balance to public balance
2. Wrapper tokens are burned
3. Original SPL tokens are released from vault back to user

### Security Features
- **Deterministic wrapper mints**: Same wrapper mint generated for same original token
- **Secure vault system**: Original tokens locked until unwrapping
- **Zero-knowledge proofs**: Transactions proven valid without revealing amounts
- **ElGamal + AES encryption**: Private keys unique to each user

## Command Line Options

- `--rpc-url`: Solana RPC endpoint (default: https://api.devnet.solana.com)
- `--keypair-path`: Path to keypair file (default: ~/.config/solana/id.json)
- `--verbose`: Enable debug logging

## Examples

Complete workflow with USDC on devnet:

```bash
# 1. Initialize wrapper for USDC
cargo run --bin wrapper_example -- init --mint 4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU

# 2. Wrap 100 USDC tokens
cargo run --bin wrapper_example -- wrap --mint 4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU --amount 100

# 3. Check wrapper status
cargo run --bin wrapper_example -- info --mint 4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU

# 4. Unwrap 50 USDC tokens back
cargo run --bin wrapper_example -- unwrap --mint 4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU --amount 50 --confidential-account <YOUR_CONFIDENTIAL_ACCOUNT>
```

## Project Structure

```
src/
├── lib.rs              # Main library exports and types
├── wrapper.rs          # Core confidential wrapper implementation
├── utils.rs            # Utility functions
├── main.rs             # Original confidential transfer demo
└── bin/
    └── wrapper_example.rs  # CLI application
```

## Dependencies

Key dependencies include:
- `solana-sdk`: Solana blockchain interaction
- `spl-token`: SPL token operations
- `spl-token-2022`: Token-2022 program with extensions
- `spl-token-client`: High-level token client
- Confidential transfer proof libraries
- `clap`: Command line argument parsing

## Troubleshooting

**"Invalid Mint" Error**: Ensure the wrapper is initialized before wrapping tokens.

**"Insufficient Balance" Error**: Make sure you have enough of the original SPL tokens and SOL for transaction fees.

**"Account Not Found" Error**: The specified mint address or account doesn't exist.

**Transaction Failures**: Check your SOL balance and network connectivity.

## Network Support

- **Devnet**: Recommended for testing
- **Mainnet-beta**: Production use (use with caution)
- **Testnet**: Limited support

## Limitations

- Requires Token-2022 program support
- Confidential transfers require proof generation (may be slow)
- Original tokens are locked in vault during wrapping period
- CLI currently supports single-user operations

## License

This project is provided as-is for educational and development purposes.