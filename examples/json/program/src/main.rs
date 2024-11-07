#![no_main]
sp1_zkvm::entrypoint!(main);

use lib::{Account, Transaction}; // Custom structs.
use serde_json::Value; // Generic JSON.

pub fn main() {
    // read generic JSON example inputs.
    let data_str = sp1_zkvm::io::read::<String>();
    let key = sp1_zkvm::io::read::<String>();

    // read custom struct example inputs.
    let mut old_account_state = sp1_zkvm::io::read::<Account>();
    let txs = sp1_zkvm::io::read::<Vec<Transaction>>();

    // do stuff with generic JSON.
    let v: Value = serde_json::from_str(&data_str).unwrap();
    let val = &v[key];

    // do stuff with custom struct.
    let new_account_state = &mut old_account_state;
    for tx in txs {
        if tx.from == new_account_state.account_name {
            new_account_state.balance -= tx.amount;
        }
        if tx.to == new_account_state.account_name {
            new_account_state.balance += tx.amount;
        }
    }
    sp1_zkvm::io::commit(&val);
    sp1_zkvm::io::commit(&new_account_state);
}
