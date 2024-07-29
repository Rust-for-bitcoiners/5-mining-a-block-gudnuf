use bitcoin::{
    absolute::LockTime,
    block::{Block, BlockHash, Header, Version},
    consensus::{Decodable, Encodable},
    hashes::sha256d::Hash,
    hex::DisplayHex,
    transaction::{TxIn, TxOut},
    Amount, OutPoint, ScriptBuf, Sequence, Target, Transaction, TxMerkleNode, Weight, Witness,
    WitnessCommitment,
};
use core::panic;
use serde_json::Value;
use std::{
    fs::{self, File},
    io::Write,
    path::Path,
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

const MAX_BLOCK_WEIGHT: Weight = Weight::from_wu(4_000_000); // 4MB

/**
 * Reads all transactions from the mempool directory and returns them as a vector of transactions.
 */
fn get_mempool_transactions() -> Vec<Transaction> {
    let mut transactions: Vec<Transaction> = Vec::new();

    // TODO: read from config file
    let mempool_dir = Path::new("./mempool");

    // if successfully read the mempool directory
    if let Ok(entries) = fs::read_dir(mempool_dir) {
        for entry in entries {
            if let Ok(entry) = entry {
                if entry.file_name().to_str().unwrap().contains("mempool") {
                    continue;
                }

                // read in and parse the JSON file
                let path = entry.path();
                let contents = fs::read(&path).expect("Could not read file");
                let json: Value = serde_json::from_slice(&contents).expect("Could not parse JSON");

                // get the hex string from the JSON
                let raw_tx = json
                    .get("hex")
                    .expect("Could not get hex")
                    .as_str()
                    .expect("Could not parse hex");

                // decode hex string into Transaction
                let bytes = hex::decode(raw_tx).expect("Could not decode hex");
                let tx = Transaction::consensus_decode(&mut bytes.as_slice())
                    .expect("Could not decode transaction");

                transactions.push(tx);
            } else {
                panic!("Could not read file: {:?}", entry);
            };
        }
    }
    println!("Found {} transactions in mempool", transactions.len());
    transactions
}

fn select_for_block(transactions: Vec<Transaction>) -> Vec<Transaction> {
    let mut block_transactions: Vec<Transaction> = Vec::new();
    let mut block_weight = Weight::ZERO;

    // TODO: select highest fee rate transactions

    // add transactions until block weight exceeds MAX_BLOCK_WEIGHT
    // TODO: leave room for coinbase transaction
    for tx in transactions {
        block_weight += tx.weight();
        if block_weight > MAX_BLOCK_WEIGHT {
            break;
        }
        block_transactions.push(tx);
    }
    block_transactions
}

fn create_coinbase_transaction(
    witness_commitment: WitnessCommitment,
    witness_reserved_value: &Vec<u8>,
) -> Transaction {
    // TOOD: make witness_commitment_script work, right now tests don't pass
    let mut witness_commitment_script = vec![0x61, 0x24, 0xaa, 0x21, 0xa9, 0xed];
    witness_commitment_script.extend_from_slice(&witness_commitment[..]);

    // construct arbitrary coinbase transaction
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::default(),
            script_sig: ScriptBuf::from_hex("0102030405060708091011121314151617181920").unwrap(), // random script
            sequence: Sequence::default(),
            witness: Witness::from_slice(&[witness_reserved_value]),
        }],
        output: vec![
            TxOut {
                // this is where witness_commitment_script goes... I think
                script_pubkey: ScriptBuf::from_hex("00").unwrap(),
                value: Amount::ZERO,
            },
            TxOut {
                // the block reward goes here
                script_pubkey: ScriptBuf::default(),
                value: Amount::from_int_btc(50),
            },
        ],
    }
}

fn create_block_template(transactions: Vec<Transaction>) -> Block {
    // placeholder header
    let header_temp = Header {
        version: Version::from_consensus(4),
        prev_blockhash: BlockHash::from_raw_hash(
            Hash::from_str("0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap(),
        ),
        merkle_root: TxMerkleNode::from_raw_hash(
            Hash::from_str("0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap(),
        ),
        time: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32,
        bits: Target::from_hex(
            "0x0000ffff00000000000000000000000000000000000000000000000000000000",
        )
        .unwrap()
        .to_compact_lossy(),
        nonce: 0,
    };

    let mut block = Block {
        header: header_temp,
        txdata: transactions.to_vec(),
    };

    // TODO: make witness_commitment work
    let witness_root = block.witness_root().unwrap();
    let witness_reserved_value = vec![0x00; 32];
    let witness_commitment =
        Block::compute_witness_commitment(&witness_root, &witness_reserved_value);

    // add coinbase transaction to block
    let coinbase = create_coinbase_transaction(witness_commitment, &witness_reserved_value);
    block.txdata[0] = coinbase;

    // compute merkle root from transactions in block
    block.header.merkle_root = block.compute_merkle_root().unwrap();
    block
}

fn mine_block(block: &mut Block) -> () {
    // TOOD: what happens when nonce overflows? Increment time?
    while !block.header.target().is_met_by(block.block_hash()) {
        block.header.nonce += 1;
    }
}

fn print_result(block: Block) {
    let mut file = File::create("out.txt").expect("Failed to create out.txt");

    // Write block header
    let encoded_header = &mut Vec::new();
    block
        .header
        .consensus_encode(encoded_header)
        .expect("Failed to encode block header");
    writeln!(file, "{}", encoded_header.as_hex()).expect("Failed to write block header");

    // Write serialized coinbase transaction
    let coinbase_tx = block.coinbase().unwrap();
    let encoded_coinbase_tx = &mut Vec::new();
    coinbase_tx
        .consensus_encode(encoded_coinbase_tx)
        .expect("Failed to encode coinbase transaction");
    writeln!(file, "{}", encoded_coinbase_tx.as_hex())
        .expect("Failed to write coinbase transaction");

    // Write transaction IDs
    for tx in block.txdata.iter() {
        writeln!(file, "{}", tx.compute_txid()).expect("Failed to write transaction ID");
    }
}

fn main() {
    println!("Collecting transactions from mempool...");
    // read all transactions from mempool into memory
    let all_transactions = get_mempool_transactions();

    // select transactions totalling less than 4MB
    let block_transactions = select_for_block(all_transactions);
    println!("Selected {} transactions", block_transactions.len());

    // create a block template with the selected transactions and placeholder header
    let mut block = create_block_template(block_transactions);

    println!("Mining block...");
    mine_block(&mut block);

    println!(
        "Target: {:?}\nBlock Hash: {:?}",
        block.header.target(),
        block.block_hash()
    );

    // output results to out.txt to run tests
    print_result(block)
}
