use clap::Parser;
use hashes::{sha256, Hash};
use secp256k1::{ecdsa, Error, Message, Secp256k1, SecretKey, Signing};
use sp1_sdk::{ProverClient, SP1Stdin};
pub const FIBONACCI_ELF: &[u8] = include_bytes!("../../../elf/riscv32im-succinct-zkvm-elf");
use std::time::{SystemTime, UNIX_EPOCH};
fn sign<C: Signing>(
    secp: &Secp256k1<C>,
    msg: &[u8],
    seckey: [u8; 32],
) -> Result<ecdsa::Signature, Error> {
    let msg = sha256::Hash::hash(msg);
    let msg = Message::from_digest_slice(msg.as_ref())?;
    let seckey = SecretKey::from_slice(&seckey)?;
    Ok(secp.sign_ecdsa(&msg, &seckey))
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(long)]
    execute: bool,
    #[clap(long)]
    prove: bool,
}

fn main() {
    sp1_sdk::utils::setup_logger();
    let args = Args::parse();
    if args.execute == args.prove {
        eprintln!("Error: You must specify either --execute or --prove");
        std::process::exit(1);
    }
    let client = ProverClient::new();
    let mut stdin = SP1Stdin::new();

    let secp = Secp256k1::new();
    let seckey = [
        59, 148, 11, 85, 134, 130, 61, 253, 2, 174, 59, 70, 27, 180, 51, 107, 94, 203, 174, 253,
        102, 39, 170, 146, 46, 252, 4, 143, 236, 12, 136, 28,
    ];
    let msg = b"This is some message";
    let signature = sign(&secp, msg, seckey).unwrap();
    let serialize_sig = signature.serialize_compact();

    stdin.write(&serialize_sig.to_vec());

    if args.execute {
        let (_output, report) = client.execute(FIBONACCI_ELF, stdin).run().unwrap();
        println!("Program executed successfully.");
        println!("Values are correct!");
        println!("Number of cycles: {}", report.total_instruction_count());
    } else {
        let (pk, vk) = client.setup(FIBONACCI_ELF);
        let system_time = SystemTime::now();
        let start_time = system_time.duration_since(UNIX_EPOCH);
        let proof = client
            .prove(&pk, stdin)
            .run()
            .expect("failed to generate proof");
        let system_time = SystemTime::now();
        println!(
            "Elapsed Proving time: {:?}",
            system_time.duration_since(UNIX_EPOCH).unwrap() - start_time.unwrap()
        );
        println!("Successfully generated proof!");
        client.verify(&proof, &vk).expect("failed to verify proof");
        println!("Successfully verified proof!");
    }
}
