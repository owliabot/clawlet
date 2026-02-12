//! Transaction building for Solana SOL and SPL token transfers.

use solana_sdk::hash::Hash;
use solana_sdk::message::Message;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::system_instruction;
use solana_sdk::transaction::Transaction;
use spl_associated_token_account::get_associated_token_address;
use spl_associated_token_account::instruction::create_associated_token_account_idempotent;

/// Builds a SOL transfer transaction (unsigned).
///
/// The caller must sign and set a recent blockhash before sending.
pub fn build_sol_transfer(from: &Pubkey, to: &Pubkey, lamports: u64) -> Transaction {
    let ix = system_instruction::transfer(from, to, lamports);
    let message = Message::new(&[ix], Some(from));
    Transaction::new_unsigned(message)
}

/// Builds an SPL token transfer transaction (unsigned).
///
/// Creates the associated token account for the recipient if needed
/// (using `create_associated_token_account_idempotent`).
pub fn build_spl_transfer(from: &Pubkey, to: &Pubkey, mint: &Pubkey, amount: u64) -> Transaction {
    let from_ata = get_associated_token_address(from, mint);
    let to_ata = get_associated_token_address(to, mint);

    let create_ata_ix =
        create_associated_token_account_idempotent(from, to, mint, &spl_token::id());

    let transfer_ix = spl_token::instruction::transfer(
        &spl_token::id(),
        &from_ata,
        &to_ata,
        from,
        &[from],
        amount,
    )
    .expect("valid transfer instruction");

    let message = Message::new(&[create_ata_ix, transfer_ix], Some(from));
    Transaction::new_unsigned(message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_sol_transfer_creates_valid_tx() {
        let from = Pubkey::new_unique();
        let to = Pubkey::new_unique();
        let tx = build_sol_transfer(&from, &to, 1_000_000);

        assert_eq!(tx.message.instructions.len(), 1);
        assert!(!tx.is_signed());
    }

    #[test]
    fn build_spl_transfer_creates_valid_tx() {
        let from = Pubkey::new_unique();
        let to = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let tx = build_spl_transfer(&from, &to, &mint, 1_000_000);

        // Should have create ATA + transfer = 2 instructions
        assert_eq!(tx.message.instructions.len(), 2);
        assert!(!tx.is_signed());
    }

    #[test]
    fn sol_transfer_different_amounts() {
        let from = Pubkey::new_unique();
        let to = Pubkey::new_unique();

        let tx1 = build_sol_transfer(&from, &to, 100);
        let tx2 = build_sol_transfer(&from, &to, 200);

        // Different amounts should produce different instruction data
        assert_ne!(
            tx1.message.instructions[0].data,
            tx2.message.instructions[0].data
        );
    }
}
