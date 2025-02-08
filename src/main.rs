use sha2::{Sha256, Digest};
use hex;

use std::env;
use std::fs::File;
use std::io::{Result, Write};

mod util;
use util::error::LibError;
use util::generate::{generate_string, read_hashes_from_file};

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    match args.get(1).map(|s| s.as_str()) {
        Some("1") => entry_point_1().await?,
        Some("2") => entry_point_1().await?,
        _ => basic_entry().await?,
    }

    Ok(())
}

async fn basic_entry() -> Result<()>{

    let tx_hashes = read_hashes_from_file("ts_hashes.json")?;
    println!("hashes: {:?}", tx_hashes);
    let tx_hashes: Vec<Vec<u8>> = tx_hashes.iter()
        .map(|s| hex::decode(s).expect("Invalid hex"))
        .collect();

    if tx_hashes.is_empty() {
        eprintln!("No valid values found in the input file.");
        return Ok(());
    }
    println!("hashes: {:?}", tx_hashes);
    let merkle_root = merkle(tx_hashes);
    println!("Merkle Root: {}", hex::encode(merkle_root));
    Ok(())
}
async fn entry_point_1() -> Result<()>{

    let mut file = File::create("ts_hashes.json")?;
    for _ in 0..10 {
        let s = generate_string(64);
        writeln!(file, "{}", s)?;
    }
    Ok(())
}

fn merkle(mut hash_list: Vec<Vec<u8>>) -> Vec<u8> {
    let mut round = 0;
    while hash_list.len() > 1 {
        round += 1;
        println!("\nRound {}: : {}", round, hash_list.len());

        let mut new_hash_list = Vec::new();
        for i in (0..hash_list.len()).step_by(2) {
            let left = &hash_list[i];
            let right = if i + 1 < hash_list.len() {
                &hash_list[i + 1]
            } else {
                left
            };

            let mut combined = Vec::new();
            combined.extend_from_slice(left);
            combined.extend_from_slice(right);
            let hash = hash2(&combined);
            new_hash_list.push(hash);
        }
        hash_list = new_hash_list;
    }
    hash_list[0].clone()
}

fn hash2(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let first_hash = hasher.finalize_reset();

    hasher.update(&first_hash);
    let second_hash = hasher.finalize();

    second_hash.to_vec()
}
