use elements::hex::ToHex;
use std::{str::FromStr, vec};

use elements::opcodes::all::OP_EQUAL;
use elements::secp256k1_zkp::SecretKey;
use elements::{
    confidential::{Asset, Value},
    encode::serialize_hex,
    hashes::{sha256, Hash},
    opcodes::all::{OP_CAT, OP_SHA256},
    pset::serialize::Serialize,
    schnorr::Keypair,
    script::Builder,
    secp256k1_zkp::{self, rand::Rng},
    taproot::{LeafVersion, TaprootBuilder, TaprootSpendInfo},
    Address, AddressParams, AssetId, LockTime, OutPoint, Sequence, Transaction, TxIn, TxOut, Txid,
};
use leptos::{mount_to_body, view};
use log::info;
use rand_chacha::rand_core::SeedableRng;

fn main() {
    _ = console_log::init_with_level(log::Level::Debug);
    console_error_panic_hook::set_once();

    let secp = secp256k1_zkp::Secp256k1::new();

    let p1_secret =
        SecretKey::from_str("0eae283124be737cfef1a2f224e252fe501614987fdc7d8afda607011bd7f969")
            .unwrap();
    let p2_secret =
        SecretKey::from_str("8302235fe68dccbeb724807416598359ffca97766684cc3fd3bd1b7d513cc0be")
            .unwrap();
    //player 1 keys
    let player_1 = Keypair::from_secret_key(&secp, &p1_secret);

    //player 2 keys
    let player_2 = Keypair::from_secret_key(&secp, &p2_secret);

    //player 1 preimage and hash
    let p1_preimage = "fd9e60387c77ff50e98a1c829381ea7e7b662b930d5980b727084901cabfafcb";
    let p1_hash = sha256::Hash::hash(p1_preimage.as_bytes());
    info!("Player 1 preimage hash: {:?}", p1_hash);
    //player 2 preimage and hash
    let p2_preimage = "68a02decb5419cfcf6ce69008903cb04e029e452a6fd3717427cbd8c7bf49239";
    let p2_hash = sha256::Hash::hash(p2_preimage.as_bytes());
    info!("Player 2 preimage hash: {:?}", p2_hash);

    let combined_hash = sha256::Hash::hash(&[p1_hash, p2_hash].concat());

    info!("Combined hash: {:?}", combined_hash);

    //create the bitcoin address
    let combined_pubkey =
        secp256k1_zkp::PublicKey::combine_keys(&[&player_1.public_key(), &player_2.public_key()])
            .expect("Failed to combine keys");

    let script = battle_script(combined_hash.serialize());

    let taproot_spend_info: TaprootSpendInfo = TaprootBuilder::new()
        .add_leaf(0, script.clone())
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

    //pick a random player to win
    let winner = if rand_chacha::ChaCha20Rng::from_entropy().gen_bool(0.5) {
        player_1
    } else {
        player_2
    };
    info!("Winner: {:?}", winner.public_key().serialize().to_hex());

    let winners_address = Address::p2tr(
        &secp,
        winner.x_only_public_key().0,
        None,
        None,
        &AddressParams::LIQUID_TESTNET,
    );

    //create spend transaction for winner to claim funds

    let txid_1 = "6470a3d43cc56f2f85290340abe5abc1536e8f225bc51a2aa02e138659c83ae6";
    let txid_1 = Txid::from_str(txid_1).unwrap();

    let input_1 = TxIn {
        previous_output: OutPoint::new(txid_1, 0),
        sequence: Sequence::default(),
        ..Default::default()
    };

    let asset_id =
        AssetId::from_str("144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49")
            .unwrap();

    let fee = 100;

    let spend = TxOut {
        value: Value::Explicit(100000 - fee),
        script_pubkey: winners_address.script_pubkey(),
        asset: Asset::Explicit(asset_id),
        ..Default::default()
    };

    let fee = TxOut::new_fee(fee, asset_id);

    let mut unsigned_tx = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![input_1],
        output: vec![spend, fee],
    };

    unsigned_tx.input[0]
        .witness
        .script_witness
        .push(p1_hash.serialize().to_vec());
    unsigned_tx.input[0]
        .witness
        .script_witness
        .push(p2_hash.serialize().to_vec());
    unsigned_tx.input[0]
        .witness
        .script_witness
        .push(script.to_bytes());

    let control_block = taproot_spend_info
        .control_block(&(script.clone(), LeafVersion::default()))
        .unwrap();
    unsigned_tx.input[0]
        .witness
        .script_witness
        .push(control_block.serialize());

    info!("Unsigned Transaction: {:?}", unsigned_tx);

    let serialized_tx = serialize_hex(&unsigned_tx);
    info!("Hex Encoded Transaction: {}", serialized_tx);

    let address_text = format!("game deposit address: {}", address);
    let txid_text = format!("Withdraw TXID: {}", serialized_tx);
    mount_to_body(|| view! { <p> {address_text} </p><p> {txid_text} </p> });
}

fn battle_script(combined_hash: Vec<u8>) -> elements::Script {
    Builder::new()
        .push_opcode(OP_CAT)
        .push_opcode(OP_SHA256)
        .push_slice(&combined_hash)
        .push_opcode(OP_EQUAL)
        .into_script()
}
