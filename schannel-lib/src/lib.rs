// Secure Channel library
// SPDX-License-Identifier: MIT
// Copyright (C) 2022 VTT Technical Research Centre of Finland Ltd

use std::net::{TcpStream, Shutdown};
use std::io::{self, Read, Write};
use rand::Rng;
use static_dh_ecdh::ecdh::ecdh::{
    ECDHNISTP384, SkP384, PkP384, KeyExchange, FromBytes, ToBytes};
use sha2::{Sha256, Digest};
use aes::Aes128;
use aes::cipher::{
    BlockEncrypt, BlockDecrypt, KeyInit,
    generic_array::GenericArray,
};

const BLOCK_SIZE: usize = 16;

pub fn ecc_keypair_gen() -> (SkP384, PkP384) {
    let random_bytes = rand::thread_rng().gen::<[u8; 32]>();
    let sk = ECDHNISTP384::<48>::generate_private_key(random_bytes);
    let pk: PkP384 = ECDHNISTP384::<48>::generate_public_key(&sk);
    (sk, pk)
}

pub fn aes_cipher_gen(sk: &SkP384, pk: &PkP384) -> Aes128 {
    // Generate shared secret
    let ss = ECDHNISTP384::<48>::generate_shared_secret(&sk, &pk);
    // AES 256-bit key generation
    let mut hasher = Sha256::new();
    hasher.update(&ss.as_ref().unwrap().to_bytes());
    let hash_result = hasher.finalize();
    let keydata = &hash_result[0..16];
    let key =  GenericArray::from_slice(&keydata);
    let cipher = Aes128::new(&key);
    cipher
}

pub fn send_pubkey(mut stream: &TcpStream, pk: &PkP384) -> io::Result<()> {
    let bytes = pk.to_bytes();
        let bytes_written = stream.write(&bytes)?;
    if bytes_written < bytes.len() {
        println!("Sent only {}/{} bytes", bytes_written, bytes.len())
    }
    stream.flush()?;
    Ok(())
}

pub fn receive_pubkey(mut stream: &TcpStream) -> Result<PkP384, io::Error> {
    const MESSAGE_SIZE: usize = 32;
    let mut received: Vec<u8> = vec![];
    let mut rx_bytes = [0u8; MESSAGE_SIZE];
    loop {
        // Read from the current data in the TcpStream
        let bytes_read = stream.read(&mut rx_bytes)?;

        // However many bytes we read, extend the `received` string bytes
        received.extend_from_slice(&rx_bytes[..bytes_read]);

        // If we didn't fill the array
        // stop reading because there's no more data (we hope!)
        if bytes_read < MESSAGE_SIZE {
            break;
        }
    }
    let pk: PkP384 = PkP384::from_bytes(&received).unwrap();
    Ok(pk)
}

pub fn pad(buffer: &mut Vec<u8>, block_size: usize) {
    let padding_size = block_size - (buffer.len() % block_size);
    buffer.resize(buffer.len() + padding_size, padding_size as u8);
}

pub fn un_pad(buffer: &mut Vec<u8>) {
    if let Some(&pad_len) = buffer.last() {
        let len = buffer.len();
        buffer.truncate(len - pad_len as usize);
    }
}

pub fn encrypt(msg: &mut Vec<u8>, cipher: &Aes128) ->  Result<Vec<u8>, io::Error> {
    pad(msg, BLOCK_SIZE);
    let data: &[u8] = &msg;
    let mut blocks = Vec::new();
    (0..data.len()).step_by(BLOCK_SIZE).for_each(|x| {
        blocks.push(GenericArray::clone_from_slice(&data[x..x + BLOCK_SIZE]));
    });
    cipher.encrypt_blocks(&mut blocks);
    let encrypted: Vec<u8> = blocks.into_iter().flatten().collect::<Vec<u8>>();
    Ok(encrypted)
}

pub fn decrypt(msg: &mut Vec<u8>, cipher: &Aes128) ->  Result<Vec<u8>, io::Error> {
    let data: &[u8] = &msg;
    let mut blocks = Vec::new();
    (0..msg.len()).step_by(BLOCK_SIZE).for_each(|x| {
        blocks.push(GenericArray::clone_from_slice(&data[x..x + BLOCK_SIZE]));
    });
    cipher.decrypt_blocks(&mut blocks);
    let mut decrypted: Vec<u8> = blocks.into_iter().flatten().collect::<Vec<u8>>();
    un_pad(&mut decrypted);
    Ok(decrypted)
}

pub fn schannel_read(mut stream: &TcpStream) -> Result<Vec<u8>, io::Error> {
    const MAX_MESSAGE_SIZE: usize = 512;
    let mut data = [0 as u8; MAX_MESSAGE_SIZE];
    stream.set_nonblocking(false).expect("set_nonblocking call failed");
    let size = match stream.read(&mut data) {
        Ok(size) => size,
        Err(err) => {
            println!("An error occurred, terminating connection with {}",
                     stream.peer_addr().unwrap());
            stream.shutdown(Shutdown::Both).unwrap();
            return Err(err);
        }
    };
    let msg: Vec<u8> = data[0..size].to_vec();
    Ok(msg)
}

pub fn schannel_write(mut stream: &TcpStream, msg: &mut Vec<u8>) -> io::Result<()> {
    let encmsg: &[u8] = &msg;
    let encmsg_written = stream.write(&encmsg)?;
    if encmsg_written < encmsg.len() {
        println!("Sent only {}/{} bytes", encmsg_written, encmsg.len())
    }
    stream.flush()?;
    Ok(())
}
