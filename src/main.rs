use elements::bitcoin::{secp256k1, transaction, TapSighashType, Witness};
use elements::encode::deserialize;
use elements::hex::{FromHex, ToHex};
use elements::schnorr::{TapTweak, TweakedKeypair};
use elements::sighash::{Prevouts, SighashCache};
use elements::{address, bitcoin, BlockHash, Script};
use leptos::ev::message;
use reqwasm::http::Request;
use serde::{Deserialize, Serialize};
use std::{str::FromStr, vec};

use elements::opcodes::all::{OP_CHECKSIGADD, OP_EQUAL, OP_NUMEQUAL, OP_NUMEQUALVERIFY};
use elements::secp256k1_zkp::{rand, Message, SecretKey};
use elements::{
    confidential::{Asset, Value},
    encode::serialize_hex,
    hashes::{sha256, Hash},
    opcodes::all::{OP_CAT, OP_SHA256},
    pset::serialize::Serialize as PsetSerialize,
    schnorr::Keypair,
    script::Builder,
    secp256k1_zkp::{self},
    taproot::{LeafVersion, TaprootBuilder, TaprootSpendInfo},
    Address, AddressParams, AssetId, LockTime, OutPoint, Sequence, Transaction, TxIn, TxOut, Txid,
};
use leptos::{mount_to_body, spawn_local, view};
use log::info;

#[derive(Debug, Serialize, Deserialize)]
struct Utxo {
    txid: String,
    vout: u32,
    status: UtxoStatus,
    value: u64,
    asset: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct UtxoStatus {
    confirmed: bool,
    block_height: u64,
    block_hash: String,
    block_time: u64,
}

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

    //oracle server will do this and send to both players
    let combined_hash = sha256::Hash::hash(&[p1_hash, p2_hash].concat());

    info!("Combined hash: {:?}", combined_hash);

    //create the bitcoin address
    let combined_pubkey =
        secp256k1_zkp::PublicKey::combine_keys(&[&player_1.public_key(), &player_2.public_key()])
            .expect("Failed to combine keys");

    let script = battle_script(combined_hash.serialize(), player_1, player_2);

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
    let winner = if rand::random() { player_1 } else { player_2 };
    info!("Winner: {:?}", winner.public_key().serialize().to_hex());

    let winners_address = Address::p2tr(
        &secp,
        winner.x_only_public_key().0,
        None,
        None,
        &AddressParams::LIQUID_TESTNET,
    );

    let address_clone = address.clone();
    let address_text = format!("game deposit address: {}", address);
    mount_to_body(|| view! { <p> {address_text} </p> });

    spawn_local(async move {
        let res_utxo = Request::get(&format!(
            "https://liquid.network/liquidtestnet/api/address/{}/utxo",
            address_clone
        ))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

        let utxos: Vec<Utxo> = serde_json::from_str(&res_utxo).expect("Failed to parse JSON");

        if utxos.is_empty() {
            return;
        }

        let inputs: Vec<TxIn> = utxos
            .iter()
            .map(|utxo| TxIn {
                previous_output: OutPoint::new(
                    elements::Txid::from_str(&utxo.txid).expect("Invalid txid format"),
                    utxo.vout,
                ),
                ..Default::default()
            })
            .collect();

        info!("Found UTXOs: {:?}", inputs);

        let mut prev_tx = Vec::new();

        for input in inputs.clone() {
            let url = format!(
                "https://liquid.network/liquidtestnet/api/tx/{}/hex",
                input.previous_output.txid
            );
            let response = Request::get(&url)
                .send()
                .await
                .unwrap()
                .text()
                .await
                .unwrap();

            let tx: Transaction = deserialize(&Vec::<u8>::from_hex(&response).unwrap()).unwrap();
            prev_tx.push(tx);
        }

        info!("Found Transactions: {:?}", prev_tx);

        let asset_id = AssetId::from_str(&utxos[0].asset).unwrap();

        let total_amount = utxos.iter().map(|utxo| utxo.value).sum::<u64>();
        let fee = 100;

        let spend = TxOut {
            value: Value::Explicit(total_amount - fee),
            script_pubkey: winners_address.script_pubkey(),
            asset: Asset::Explicit(asset_id),
            ..Default::default()
        };

        let fee = TxOut::new_fee(fee, asset_id);

        let mut unsigned_tx = Transaction {
            version: 2,
            lock_time: LockTime::ZERO,
            input: inputs,
            output: vec![spend, fee],
        };

        let control_block = taproot_spend_info
            .control_block(&(script.clone(), LeafVersion::default()))
            .unwrap();

        for (index, input) in unsigned_tx.input.iter_mut().enumerate() {
            let mut binding = Vec::new();

            prev_tx[index].output.iter().for_each(|output| {
                binding.push(output.clone());
            });

            let prevouts = Prevouts::All(&binding);

            info!("Prevouts: {:?}", prevouts);

            input
                .witness
                .script_witness
                .push(p1_hash.serialize().to_vec());
            input
                .witness
                .script_witness
                .push(p2_hash.serialize().to_vec());

            input.witness.script_witness.push(script.to_bytes());
            input.witness.script_witness.push(control_block.serialize());

            // let mut sighasher = SighashCache::new(&mut unsigned_tx);
            // let sighash = sighasher
            //     .taproot_script_spend_signature_hash(
            //         input_index,
            //         &prevouts,

            //         TapSighashType::Default,
            //         BlockHash::all_zeros(),
            //     )
            //     .expect("failed to construct sighash");

            // // Sign the sighash using the secp256k1 library (exported by rust-bitcoin).
            // let tweaked: TweakedKeypair = winner.tap_tweak(&secp, None);
            // let msg = secp256k1::Message::from_digest_slice(sighash.as_ref()).expect("should be cryptographically secure hash")
            // let signature = secp.sign_schnorr(&msg, &tweaked.to_inner());
            // input.witness.script_witness.push(signature.serialize().to_vec());
        }

        info!("Unsigned Transaction: {:?}", unsigned_tx);

        let serialized_tx = serialize_hex(&unsigned_tx);
        info!("Hex Encoded Transaction: {}", serialized_tx);

        let txid_text = format!("Withdraw TXID: {}", serialized_tx);

        let res = Request::post("https://liquid.network/liquidtestnet/api/tx")
            .body(serialized_tx)
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();

        info!("TXID: {:?}", res);

        mount_to_body(|| view! { <p> {txid_text} </p> });
    });
}

fn battle_script(combined_hash: Vec<u8>, keypair1: Keypair, keypair2: Keypair) -> elements::Script {
    Builder::new()
        .push_key(&keypair1.public_key().into())
        .push_opcode(OP_CHECKSIGADD)
        .push_key(&keypair2.public_key().into())
        .push_opcode(OP_CHECKSIGADD)
        .push_int(1)
        .push_opcode(OP_NUMEQUALVERIFY)
        .push_opcode(OP_CAT)
        .push_opcode(OP_SHA256)
        .push_slice(&combined_hash)
        .push_opcode(OP_EQUAL)
        .into_script()
}
