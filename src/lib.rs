/*******************************************************************************
*   (c) 2018, 2019 ZondaX GmbH
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/
//! Provider for Ledger Cosmos validator app

#[macro_use]
extern crate quick_error;

#[cfg(test)]
#[macro_use]
extern crate matches;

#[cfg(test)]
extern crate sha2;

#[cfg(test)]
extern crate ed25519_dalek;

#[cfg(test)]
#[macro_use]
extern crate lazy_static;

extern crate byteorder;
extern crate ledger;

use byteorder::{LittleEndian, WriteBytesExt};
use ledger::{ApduAnswer, ApduCommand};
use std::io::BufWriter;

const CLA: u8 = 0x55; // Use 0x55 for the user App (0x56 for the validator app) see https://github.com/cosmos/ledger-cosmos-go/blob/a4f5d0465791fc1cb2d6543f861833ab510d9801/user_app.go#L28
const INS_GET_VERSION: u8 = 0x00;
const INS_PUBLIC_KEY_ED25519: u8 = 0x01;
const INS_PUBLIC_KEY_SECP256K1: u8 = 0x04;
const INS_SIGN_ED25519: u8 = 0x02;
const INS_SIGN_SECP256K1: u8 = 0x02;

const USER_MESSAGE_CHUNK_SIZE: usize = 250;

const PATH: [u32; 5] = [44, 118, 0, 0, 0]; // BIP44 path, must match https://github.com/rumos-io/gears/blob/a40fb526a3fff00db336346bb124bac69cedffc0/keyring/src/key_pair/secp256k1_key_pair.rs#L17
const HARDENED_COUNT: usize = 3; // https://github.com/cosmos/ledger-cosmos-go/blob/a4f5d0465791fc1cb2d6543f861833ab510d9801/user_app.go#L161
const HRP: &[u8; 6] = b"cosmos";

quick_error! {
    #[derive(Debug)]
    pub enum Error {
        InvalidVersion{
            display("This version is not supported")
        }
        InvalidEmptyMessage{
            display("message cannot be empty")
        }
        InvalidMessageSize{
            display("message size is invalid (too big)")
        }
        InvalidPK{
            display("received an invalid PK")
        }
        NoSignature {
            display("received no signature back")
        }
        InvalidSignature {
            display("received an invalid signature")
        }
        InvalidDerivationPath {
            display("invalid derivation path")
        }
        Ledger ( err: ledger::Error ) {
            from()
            display("ledger error")
            display("Ledger error: {}", err)
            source(err)
        }
    }
}

pub struct CosmosValidatorApp {
    app: ledger::LedgerApp,
}

unsafe impl Send for CosmosValidatorApp {}

#[derive(Debug)]
#[allow(dead_code)]
pub struct Version {
    mode: u8,
    major: u8,
    minor: u8,
    patch: u8,
}

// Based on https://github.com/cosmos/ledger-cosmos-go/blob/a4f5d0465791fc1cb2d6543f861833ab510d9801/common.go#L92C1-L106C2
fn get_bip32_bytes_v2() -> [u8; 20] {
    let mut path = PATH.to_vec();
    for (index, i) in &mut path.iter_mut().enumerate() {
        if index < HARDENED_COUNT {
            *i |= 0x8000_0000;
        }
    }

    let mut message = [0u8; 20];
    {
        let mut writer = BufWriter::new(&mut message[..]);
        for v in path {
            writer
                .write_u32::<LittleEndian>(v)
                .expect("path is 5*4=20 bytes long and the write buffer is 20 bytes long");
        }
    }

    message
}

impl CosmosValidatorApp {
    pub fn connect() -> Result<Self, Error> {
        let app = ledger::LedgerApp::new()?;
        Ok(CosmosValidatorApp { app })
    }

    pub fn version(&self) -> Result<Version, Error> {
        let command = ApduCommand {
            cla: CLA,
            ins: INS_GET_VERSION,
            p1: 0x00,
            p2: 0x00,
            length: 0,
            data: Vec::new(),
        };

        let response = self.app.exchange(command)?;

        // TODO: this is just temporary, ledger errors should check for 0x9000
        if response.retcode != 0x9000 {
            return Err(Error::InvalidVersion);
        }

        let version = Version {
            mode: response.data[0],
            major: response.data[1],
            minor: response.data[2],
            patch: response.data[3],
        };

        Ok(version)
    }

    pub fn public_key(&self) -> Result<[u8; 32], Error> {
        let command = ApduCommand {
            cla: CLA,
            ins: INS_PUBLIC_KEY_ED25519,
            p1: 0x00,
            p2: 0x00,
            length: 0,
            data: Vec::new(),
        };

        match self.app.exchange(command) {
            Ok(response) => {
                if response.retcode != 0x9000 {
                    println!("WARNING: retcode={:X?}", response.retcode);
                }

                if response.data.len() != 32 {
                    return Err(Error::InvalidPK);
                }

                let mut array = [0u8; 32];
                array.copy_from_slice(&response.data[..32]);
                Ok(array)
            }
            Err(err) => {
                // TODO: Friendly error
                return Err(Error::Ledger(err));
            }
        }
    }

    /// Returns the pubkey (compressed)
    pub fn public_key_secp256k1(&self) -> Result<[u8; 33], Error> {
        let bip32path = get_bip32_bytes_v2();

        let mut data = vec![HRP.len() as u8];
        data.extend(HRP);
        data.extend(bip32path);
        let data_length = data.len();

        let command = ApduCommand {
            cla: CLA,
            ins: INS_PUBLIC_KEY_SECP256K1,
            p1: 0x00, // require confirmation y/n
            p2: 0x00,
            length: data_length as u8,
            data,
        };

        let response = self.app.exchange(command)?;

        if response.retcode != 0x9000 {
            println!("WARNING: retcode={:X?}", response.retcode);
        }

        if response.data.len() < 35 + data_length {
            return Err(Error::InvalidPK);
        }

        //let addr = response.data.get(33..).expect("data slice has length > 33");
        //let addr = String::from_utf8_lossy(addr);

        let mut pub_key = [0u8; 33];
        pub_key.copy_from_slice(&response.data.get(..33).expect("data slice has length > 33"));
        Ok(pub_key)
    }

    // Based on https://github.com/cosmos/ledger-cosmos-go/blob/a4f5d0465791fc1cb2d6543f861833ab510d9801/user_app.go#L225
    pub fn sign_v2(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let bip32path = get_bip32_bytes_v2();

        let command = ApduCommand {
            cla: CLA,
            ins: INS_SIGN_SECP256K1,
            p1: 0x00,
            p2: 0x01,
            length: 20u8,
            data: bip32path.into(),
        };

        let _response = self.app.exchange(command)?;

        let chunks = message.chunks(USER_MESSAGE_CHUNK_SIZE);
        let packet_count = chunks.len();

        if packet_count > 255 {
            return Err(Error::InvalidMessageSize);
        }

        if packet_count == 0 {
            return Err(Error::InvalidEmptyMessage);
        }

        let mut response: ApduAnswer = ApduAnswer {
            data: vec![],
            retcode: 0,
        };

        let mut payload_desc = 1;
        // Send message chunks
        for (packet_idx, chunk) in chunks.enumerate() {
            if packet_idx == packet_count - 1 {
                payload_desc = 2;
            }
            let command = ApduCommand {
                cla: CLA,
                ins: INS_SIGN_SECP256K1,
                p1: payload_desc,
                p2: 0x01, // only values of SIGN_MODE_LEGACY_AMINO (P2=0) and SIGN_MODE_TEXTUAL (P2=1) are allowed
                length: chunk.len() as u8,
                data: chunk.to_vec(),
            };
            response = self.app.exchange(command)?;
        }

        if response.data.len() == 0 && response.retcode == 0x9000 {
            return Err(Error::NoSignature);
        }

        // response data is not a fixed length,see https://bitcoin.stackexchange.com/questions/77191/what-is-the-maximum-size-of-a-der-encoded-ecdsa-signature
        Ok(response.data)
    }

    // Sign message
    pub fn sign(&self, message: &[u8]) -> Result<[u8; 64], Error> {
        let chunks = message.chunks(USER_MESSAGE_CHUNK_SIZE);

        if chunks.len() > 255 {
            return Err(Error::InvalidMessageSize);
        }

        if chunks.len() == 0 {
            return Err(Error::InvalidEmptyMessage);
        }

        let packet_count = chunks.len() as u8;
        let mut response: ApduAnswer = ApduAnswer {
            data: vec![],
            retcode: 0,
        };

        // Send message chunks
        for (packet_idx, chunk) in chunks.enumerate() {
            let _command = ApduCommand {
                cla: CLA,
                ins: INS_SIGN_ED25519,
                p1: (packet_idx + 1) as u8,
                p2: packet_count,
                length: chunk.len() as u8,
                data: chunk.to_vec(),
            };

            response = self.app.exchange(_command)?;
        }

        if response.data.is_empty() && response.retcode == 0x9000 {
            return Err(Error::NoSignature);
        }

        // Last response should contain the answer
        if response.data.len() != 64 {
            return Err(Error::InvalidSignature);
        }

        let mut array = [0u8; 64];
        array.copy_from_slice(&response.data[..64]);
        Ok(array)
    }
}

#[cfg(test)]
mod tests {
    use crate::ed25519_dalek::Verifier;
    use std::sync::Mutex;
    use std::time::Instant;

    use crate::{CosmosValidatorApp, Error};

    lazy_static! {
        static ref APP: Mutex<CosmosValidatorApp> =
            Mutex::new(CosmosValidatorApp::connect().unwrap());
    }

    fn get_fake_proposal(index: u64, round: i64) -> Vec<u8> {
        use byteorder::{LittleEndian, WriteBytesExt};
        let other: [u8; 12] = [
            0xb, 0x8, 0x80, 0x92, 0xb8, 0xc3, 0x98, 0xfe, 0xff, 0xff, 0xff, 0x1,
        ];

        let mut message = Vec::new();
        message.write_u8(0).unwrap(); // (field_number << 3) | wire_type

        message.write_u8(0x08).unwrap(); // (field_number << 3) | wire_type
        message.write_u8(0x01).unwrap(); // PrevoteType

        message.write_u8(0x11).unwrap(); // (field_number << 3) | wire_type
        message.write_u64::<LittleEndian>(index).unwrap();

        message.write_u8(0x19).unwrap(); // (field_number << 3) | wire_type
        message.write_i64::<LittleEndian>(round).unwrap();

        // remaining fields (timestamp, not checked):
        message.write_u8(0x22).unwrap(); // (field_number << 3) | wire_type
        message.extend_from_slice(&other);

        // Increase index
        message[0] = message.len() as u8 - 1;
        message
    }

    #[test]
    fn version() {
        let app = APP.lock().unwrap();

        let resp = app.version();

        match resp {
            Ok(version) => {
                println!("mode  {}", version.mode);
                println!("major {}", version.major);
                println!("minor {}", version.minor);
                println!("patch {}", version.patch);

                assert_eq!(version.mode, 0xFF);
                assert_eq!(version.major, 0x00);
                assert!(version.minor >= 0x04);
            }
            Err(err) => {
                eprintln!("Error: {:?}", err);
            }
        }
    }

    #[test]
    fn public_key() {
        let app = APP.lock().unwrap();
        let resp = app.public_key();

        match resp {
            Ok(pk) => {
                assert_eq!(pk.len(), 32);
                println!("PK {:0X?}", pk);
            }
            Err(err) => {
                eprintln!("Error: {:?}", err);
                panic!()
            }
        }
    }

    #[test]
    fn sign_empty() {
        let app = APP.lock().unwrap();

        let some_message0 = b"";

        let signature = app.sign(some_message0);
        assert!(signature.is_err());
        assert!(matches!(
            signature.err().unwrap(),
            Error::InvalidEmptyMessage
        ));
    }

    #[test]
    fn sign_verify() {
        let app = APP.lock().unwrap();

        let some_message1 = get_fake_proposal(5, 0);
        app.sign(&some_message1).unwrap();

        let some_message2 = get_fake_proposal(6, 0);
        match app.sign(&some_message2) {
            Ok(sig) => {
                use ed25519_dalek::Signature;
                use ed25519_dalek::VerifyingKey;

                println!("{:#?}", sig.to_vec());

                // First, get public key
                let public_key_bytes = app.public_key().unwrap();
                let public_key = VerifyingKey::from_bytes(&public_key_bytes).unwrap();
                let signature = Signature::from_bytes(&sig);

                // Verify signature
                assert!(public_key.verify(&some_message2, &signature).is_ok());
            }
            Err(e) => {
                println!("Err {:#?}", e);
                panic!();
            }
        }
    }

    #[test]
    fn sign_many() {
        let app = APP.lock().unwrap();

        // First, get public key
        let _resp = app.public_key().unwrap();

        // Now send several votes
        for index in 50u8..254u8 {
            let some_message1 = [
                0x8,  // (field_number << 3) | wire_type
                0x1,  // PrevoteType
                0x11, // (field_number << 3) | wire_type
                index, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,  // height
                0x19, // (field_number << 3) | wire_type
                0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,  // round
                0x22, // (field_number << 3) | wire_type
                // remaining fields (timestamp):
                0xb, 0x8, 0x80, 0x92, 0xb8, 0xc3, 0x98, 0xfe, 0xff, 0xff, 0xff, 0x1,
            ];

            let signature = app.sign(&some_message1);
            match signature {
                Ok(sig) => {
                    println!("{:#?}", sig.to_vec());
                }
                Err(e) => {
                    println!("Err {:#?}", e);
                    panic!();
                }
            }
        }
    }

    #[test]
    fn quick_benchmark() {
        let app = APP.lock().unwrap();

        // initialize app with a vote
        let msg = get_fake_proposal(0, 100);
        app.sign(&msg).unwrap();

        let start = Instant::now();
        // Now send several votes
        for i in 1u64..20u64 {
            app.sign(&get_fake_proposal(i, 100)).unwrap();
        }
        let duration = start.elapsed();
        println!("Elapsed {:?}", duration);
    }
}
