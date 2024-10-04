#![no_main]
use hashes::{sha256, Hash};
use secp256k1::{ecdsa, Error, Message, PublicKey, Secp256k1, Verification};
sp1_zkvm::entrypoint!(main);
fn verify<C: Verification>(
    secp: &Secp256k1<C>,
    msg: &[u8],
    sig: [u8; 64],
    pubkey: [u8; 33],
) -> Result<bool, Error> {
    let msg = sha256::Hash::hash(msg);
    let msg = Message::from_digest_slice(msg.as_ref())?;
    let sig = ecdsa::Signature::from_compact(&sig)?;
    let pubkey = PublicKey::from_slice(&pubkey)?;
    for _i in 0..49 {
        assert!(secp.verify_ecdsa(&msg, &sig, &pubkey).is_ok());
    }
    Ok(secp.verify_ecdsa(&msg, &sig, &pubkey).is_ok())
}

pub fn main() {
    let secp = Secp256k1::new();
    let pubkey = [
        2, 29, 21, 35, 7, 198, 183, 43, 14, 208, 65, 139, 14, 112, 205, 128, 231, 245, 41, 91, 141,
        134, 245, 114, 45, 63, 82, 19, 251, 210, 57, 79, 54,
    ];
    let sig_serialized: Vec<u8> = sp1_zkvm::io::read::<Vec<u8>>();
    let msg = b"This is some message";
    assert!(verify(&secp, msg, sig_serialized.try_into().unwrap(), pubkey).unwrap());
}
