// Secure Channel client
// SPDX-License-Identifier: MIT
// Copyright (C) 2022 VTT Technical Research Centre of Finland Ltd

use std::str;
use std::env;
use std::net::{TcpStream, Shutdown};
use std::io::{self, stdin, stdout, Read, Write};
use rand::Rng;
use static_dh_ecdh::ecdh::ecdh::PkP384;
use static_dh_ecdh::ecdh::ecdh::ToBytes;
use static_dh_ecdh::ecdh::ecdh::FromBytes;
use schannel_lib::*;

fn usage(name: &String) {
    println!("Usage: {} [--check] hostname:portnumber", name);
}

fn parse_options(args: Vec<String>) -> (bool, String) {
    let mut attestation_check: bool = false;
    let mut hostname : String = String::new();
    for i in 1..args.len() {
        if args[i].eq("--check") {
            attestation_check = true;
        } else {
            hostname.push_str(&args[i]);
        }
    }
    (attestation_check, hostname)
}

// Send a service request
//
// The request include a nonce value and a public key of the client.
// The size of the nonce is passed in the first byte.
pub fn send_request(mut stream: &TcpStream, nonce: &Vec<u8>, pk: &PkP384) -> io::Result<()> {
    let mut buffer: Vec<u8> = Vec::new();
    buffer.push(nonce.len() as u8);
    buffer.extend(nonce);
    let bytes = pk.to_bytes();
    buffer.extend(bytes);
    let bytes_written = stream.write(&buffer)?;
    println!("{} bytes written", bytes_written);
    stream.flush()?;
    Ok(())
}

// Receive a service reply from the schannel-host
//
// Server's public key and an attestation report will be received.
pub fn receive_reply(mut stream: &TcpStream) -> Result<(PkP384, Vec<u8>), io::Error> {
    const MAX_MESSAGE_SIZE: usize = 512;
    let mut received: Vec<u8> = vec![];
    let mut attestation: Vec<u8> = vec![];
    let mut rx_bytes = [0u8; MAX_MESSAGE_SIZE];
    loop {
        // Read from the current data in the TcpStream
        let bytes_read = match stream.read(&mut rx_bytes) {
            Ok(bytes_read) => bytes_read,
            Err(e) => { return Err(e); },
        };
        println!("{} bytes read", bytes_read);
        let pubkey_len = rx_bytes[0] as usize;
        received.extend_from_slice(&rx_bytes[1..pubkey_len + 1]);
        attestation.extend_from_slice(&rx_bytes[pubkey_len + 1 .. bytes_read]);

        // If we didn't fill the array
        // stop reading because there's no more data (we hope!)
        if bytes_read < MAX_MESSAGE_SIZE {
            break;
        }
    }
    let pk: PkP384 = PkP384::from_bytes(&received).unwrap();
    Ok((pk, attestation))
}


fn main() -> io::Result<()>  {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 || args.len() > 3 {
        usage(&args[0]);
        return Ok(());
    }
    let (attestation_check, hostname) = parse_options(args);

    println!("Hostname: {}", hostname);

    // Generate ECDH-P384 private and public key
    let (sk, pk) = ecc_keypair_gen();

    let stream = TcpStream::connect(&hostname)?;
    println!("Successfully connected to {}", hostname);

    // Send own Elliptic Curve public key to the server
    let nonce: Vec<u8> = rand::thread_rng().gen::<[u8; 9]>().to_vec();
    println!("Nonce {:02X?} Len: {}", nonce, nonce.len());
    match send_request(&stream, &nonce, &pk) {
        Ok(_) => (),
        Err(e) => return Err(e),
    };

    // Receive server's public key and attestation report
    let (server_pk, attestation) = match receive_reply(&stream) {
        Ok((server_pk, attestation)) => (server_pk, attestation),
        Err(e) => return Err(e),
    };
    println!("Attestation report: {:02X?}", attestation);
    if attestation_check {
        // TODO: Verify attestation report
        println!("Attestation check TBD");
    }

    // Generate AES128 cipher using client's private key and server's pubkey
    let cipher = aes_cipher_gen(&sk, &server_pk);

    loop {
        // Read text message from console
        let mut text = String::new();
        println!("Please enter some text: ");
        let _ = stdout().flush();
        stdin().read_line(&mut text).expect("Did not enter a correct string");
        if let Some('\n') = text.chars().next_back() {
            text.pop();
        }
        if let Some('\r') = text.chars().next_back() {
            text.pop();
        }
        println!("You typed: {}", text);
        let mut data = text.as_bytes().to_vec();
        let mut encrypted : Vec<u8> = encrypt(&mut data, &cipher).unwrap();
        match schannel_write(&stream, &mut encrypted) {
            Ok(v) => v,
            Err(_) => {
                println!("An error occurred, terminating connection with {}",
                         stream.peer_addr().unwrap());
                stream.shutdown(Shutdown::Both).unwrap();
            }
        }

        if text.len() == 1 && text.eq("q") {
            break;
        }

        let mut received: Vec<u8> = match schannel_read(&stream) {
            Ok(received) => received,
            Err(_) => panic!("Read error"),
        };
        let ivec: Vec<u8> = decrypt(&mut received, &cipher).unwrap();
        let decmsg: &[u8] = &ivec;
        let s = match str::from_utf8(decmsg) {
            Ok(v) => v,
            Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
        };
        println!("result: {}", s);
    }

    println!("Terminated.");
    Ok(())
}
