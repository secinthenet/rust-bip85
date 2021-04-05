use std::env;
use std::num::ParseIntError;
use std::str::FromStr;

use bitcoin::network::constants::Network;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::util::bip32::ExtendedPrivKey;

use bip85;

// https://stackoverflow.com/a/52992629/1014208
fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let header: String = args[1].chars().skip(1).take(3).collect();
    let root: ExtendedPrivKey;
    if header == "prv" {
        root = ExtendedPrivKey::from_str(&args[1]).unwrap();
    } else {
        if args[1].len() % 2 != 0 {
            eprintln!("Invalid seed: must have an even number of chars");
            std::process::exit(1);
        }
        if args[1].len() < 32 || args[1].len() > 128 {
            eprintln!("Invalid seed: must be 16 to 64 bytes");
            std::process::exit(1);
        }
        root =
            ExtendedPrivKey::new_master(Network::Bitcoin, decode_hex(&args[1]).unwrap().as_slice())
                .unwrap();
    }

    let secp = Secp256k1::new();
    let mnemonic = bip85::to_mnemonic(&secp, &root, 12, 0).unwrap();
    println!("12-word mnemonic:\n{}", mnemonic);

    let mnemonic = bip85::to_mnemonic(&secp, &root, 24, 0).unwrap();
    println!("24-word mnemonic:\n{}", mnemonic);
}
