use elements::{
    hashes::{sha256, Hash},
    opcodes::all::{OP_CAT, OP_CHECKSIG, OP_ELSE, OP_ENDIF, OP_EQUALVERIFY, OP_HASH256, OP_IF},
    pset::serialize::Serialize,
    script::Builder,
    secp256k1_zkp::{self, rand::Rng, PublicKey},
    taproot::{TaprootBuilder, TaprootSpendInfo},
    Address, AddressParams,
};
use leptos::{mount_to_body, view};
use log::info;
use rand_chacha::rand_core::SeedableRng;

fn main() {
    _ = console_log::init_with_level(log::Level::Debug);
    console_error_panic_hook::set_once();

    //player 1 keys
    let secp = secp256k1_zkp::Secp256k1::new();
    //this needs to be a different seed for prod
    let mut rng_1 = rand_chacha::ChaCha20Rng::from_entropy();
    let player_1 = secp.generate_keypair(&mut rng_1);
    info!("Player 1 public key: {:?}", player_1.1);
    //player 2 keys
    //this needs to be a different seed for prod
    let mut rng_2 = rand_chacha::ChaCha20Rng::from_entropy();
    let player_2 = secp.generate_keypair(&mut rng_2);
    info!("Player 2 public key: {:?}", player_2.1);

    //player 1 preimage and hash
    let p1_preimage = rand_chacha::ChaCha20Rng::from_entropy().get_seed();
    let p1_hash = sha256::Hash::hash(&p1_preimage);
    info!("Player 1 preimage: {:?}", p1_preimage);
    info!("Player 1 preimage hash: {:?}", p1_hash);
    //player 2 preimage and hash
    let p2_preimage = rand_chacha::ChaCha20Rng::from_entropy().get_seed();
    let p2_hash = sha256::Hash::hash(&p2_preimage);
    info!("Player 2 preimage: {:?}", p2_preimage);
    info!("Player 2 preimage hash: {:?}", p2_hash);

    //create the bitcoin address
    let combined_pubkey = secp256k1_zkp::PublicKey::combine_keys(&[&player_1.1, &player_2.1])
        .expect("Failed to combine keys");

    let combined_hash = sha256::Hash::hash(&[p1_hash, p2_hash].concat());

    let script = battle_script(combined_hash.serialize(), player_1.1, player_2.1);

    let taproot_spend_info: TaprootSpendInfo = TaprootBuilder::new()
        .add_leaf(0, script)
        .unwrap()
        .finalize(&secp, combined_pubkey.into())
        .unwrap();

    info!("Taproot spend info: {:?}", taproot_spend_info);

    let address = Address::p2tr_tweaked(
        taproot_spend_info.output_key(),
        None,
        &AddressParams::LIQUID_TESTNET,
    );

    info!("Address: {:?}", address);

    // let script_test = format!("script used: {:?}", taproot_spend_info.as_script_map());
    let address_text = format!("game deposit address: {}", address);

    mount_to_body(|| view! { <p> {address_text} </p>});

    //pick a random player to win
    let winner = if rand_chacha::ChaCha20Rng::from_entropy().gen_bool(0.5) {
        player_1
    } else {
        player_2
    };
    info!("Winner: {:?}", winner.1);

    //create spend transaction for winner to claim funds
}

// <provided preimage1>
// SHA256
// <provided preimage2>
// SHA256
// OP_CAT // Concatenates preimage1 and preimage2
// SHA256
// <combined_hash> // Push the expected hash onto the stack
// EQUALVERIFY // Check if the computed hash equals the expected hash
// // Now check if either player's signature is valid
// IF
//     <Player 1's pubkey> CHECKSIG
// ELSE
//     <Player 2's pubkey> CHECKSIG
// ENDIF

fn battle_script(
    combined_hash: Vec<u8>,
    public_key_1: PublicKey,
    public_key_2: PublicKey,
) -> elements::Script {
    Builder::new()
        .push_opcode(OP_HASH256)
        .push_opcode(OP_HASH256)
        .push_opcode(OP_CAT)
        .push_opcode(OP_HASH256)
        .push_slice(&combined_hash)
        .push_opcode(OP_EQUALVERIFY)
        .push_opcode(OP_IF)
        .push_slice(&public_key_1.serialize())
        .push_opcode(OP_CHECKSIG)
        .push_opcode(OP_ELSE)
        .push_slice(&public_key_2.serialize())
        .push_opcode(OP_CHECKSIG)
        .push_opcode(OP_ENDIF)
        .into_script()
}
