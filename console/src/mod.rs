//! a rabe console application.
//!
//! * Developped by Georg Bramm, Fraunhofer AISEC
//! * Date: 02/2021
//!
extern crate base64;
extern crate blake2_rfc;
extern crate rand;
extern crate serde;
extern crate rabe;
extern crate deflate;
extern crate inflate;
extern crate serde_json;
extern crate serde_derive;
#[macro_use]
extern crate clap;
extern crate serde_cbor;

use base64::{decode, encode};
use clap::{App, Arg, ArgMatches, SubCommand};
use crate::rabe::{
    RabeError,
    schemes::yct14,
    utils::{
        policy::pest::PolicyLanguage,
        file::{write_file, read_file, read_raw, write_from_vec, read_to_vec}
    }
};
use serde::Serialize;
use serde_cbor::{
    from_slice,
    ser::to_vec_packed
};
use std::{
    process,
    path::Path
};

// File extensions
const CT_EXTENSION: &'static str = "ct";
const KEY_EXTENSION: &'static str = "key";
const DOT: &'static str = ".";

// Object names
const ATTRIBUTES: &'static str = "attribute";
const POLICY: &'static str = "policy";
const NAME: &'static str = "name";
const LANG: &'static str = "lang";
const FILE: &'static str = "file";

// Default file names
const MSK_FILE: &'static str = "msk";
const PK_FILE: &'static str = "pk";
const SK_FILE: &'static str = "sk";

// Key file header and footer
const SK_BEGIN: &'static str = "-----BEGIN SECRET KEY-----\n";
const SK_END: &'static str = "\n-----END SECRET KEY-----";
const MSK_BEGIN: &'static str = "-----BEGIN MASTER SECRET KEY-----\n";
const MSK_END: &'static str = "\n-----END MASTER SECRET KEY-----";
const PK_BEGIN: &'static str = "-----BEGIN PUBLIC KEY-----\n";
const PK_END: &'static str = "\n-----END PUBLIC KEY-----";
const CT_BEGIN: &'static str = "-----BEGIN CIPHERTEXT-----\n";
const CT_END: &'static str = "\n-----END CIPHERTEXT-----";

// Application commands
const CMD_SETUP: &'static str = "setup";
const CMD_KEYGEN: &'static str = "keygen";
const CMD_ENCRYPT: &'static str = "encrypt";
const CMD_DECRYPT: &'static str = "decrypt";

fn main() {
    arg_enum! {
        #[derive(Debug)]
        enum Scheme {
            YCT14
        }
    }
    arg_enum! {
        #[derive(Debug)]
        enum Lang {
            Human,
            Json,
        }
    }
    // Default file names
    let _msk_default = [MSK_FILE, DOT, KEY_EXTENSION].concat();
    let _pk_default = [PK_FILE, DOT, KEY_EXTENSION].concat();
    let _sk_default = [SK_FILE, DOT, KEY_EXTENSION].concat();

    let _abe_app = App::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!("\n"))
        .about(crate_description!())
        .subcommand(
            // Setup
            SubCommand::with_name(CMD_SETUP)
                .about("sets up a new scheme, creates the msk and pk or gp.")
                .arg(
                    Arg::with_name(ATTRIBUTES)
                        .required(true)
                        .takes_value(true)
                        .multiple(true)
                        .help("attributes to use."),
                )
        )
        .subcommand(
            // Keygen
            SubCommand::with_name(CMD_KEYGEN)
                .about(
                    "creates a user key sk using a policy.",
                )
                .arg(
                    Arg::with_name(POLICY)
                        .required(true)
                        .takes_value(true)
                        .help("policy to generate."),
                )
                .arg(
                    Arg::with_name(MSK_FILE)
                        .required(false)
                        .takes_value(true)
                        .default_value(&_msk_default)
                        .help("master secret key file."),
                )
                .arg(
                    Arg::with_name(PK_FILE)
                        .required(false)
                        .takes_value(true)
                        .default_value(&_pk_default)
                        .help("public key file."),
                )
                .arg(
                    Arg::with_name(SK_FILE)
                        .required(false)
                        .takes_value(true)
                        .default_value(&_sk_default)
                        .help("user key file."),
                )
        )
        .subcommand(
            // Encrypt
            SubCommand::with_name(CMD_ENCRYPT)
                .about(
                    "encrypts a file using attributes.",
                )
                .arg(
                    Arg::with_name(FILE)
                        .required(true)
                        .takes_value(true)
                        .help("the file to encrypt."),
                )
                .arg(
                    Arg::with_name(ATTRIBUTES)
                        .required(true)
                        .takes_value(true)
                        .multiple(true)
                        .help("the attribute(s) to use."),
                )
                .arg(
                    Arg::with_name(PK_FILE)
                        .required(false)
                        .takes_value(true)
                        .default_value(&_pk_default)
                        .last(true)
                        .help("public key file."),
                ),
        )
        .subcommand(
            // Decrypt
            SubCommand::with_name(CMD_DECRYPT)
                .about("decrypts a file using a key.")
                .arg(
                    Arg::with_name(FILE)
                        .required(true)
                        .takes_value(true)
                        .help("ciphertext to decrypt."),
                )
                .arg(
                    Arg::with_name(SK_FILE)
                        .required(false)
                        .takes_value(true)
                        .default_value(&_sk_default)
                        .help("user key file."),
                )
        )
        .get_matches();

    if let Err(e) = run(_abe_app) {
        println!("Application error: {}", e);
        process::exit(1);
    }

    fn run(argument_matches: ArgMatches) -> Result<(), RabeError> {
        let _scheme = Scheme::YCT14;
        let mut _lang;
        if let Some(_l) = argument_matches.value_of(LANG) {
            _lang = match _l.to_lowercase().as_str() {
                "json" => PolicyLanguage::JsonPolicy,
                _ => PolicyLanguage::HumanPolicy,
            };
        } else {
            _lang = PolicyLanguage::HumanPolicy;
        }
        let _json: bool = true;
        match argument_matches.subcommand() {
            (CMD_SETUP, Some(arguments)) => run_setup(arguments, _scheme, _json),
            (CMD_KEYGEN, Some(arguments)) => run_keygen(arguments, _scheme, _lang, _json),
            (CMD_ENCRYPT, Some(arguments)) => run_encrypt(arguments, _scheme, _lang, _json),
            (CMD_DECRYPT, Some(arguments)) => run_decrypt(arguments, _scheme, _lang, _json),
            _ => Ok(()),
        }
    }

    fn run_setup(arguments: &ArgMatches, _scheme: Scheme, _json: bool) -> Result<(), RabeError> {
        let mut _msk_file = String::from("");
        let mut _pk_file = String::from("");
        let mut _gp_file = String::from("");
        match arguments.value_of(MSK_FILE) {
            None => {
                _msk_file.push_str(&MSK_FILE);
                _msk_file.push_str(&DOT);
                _msk_file.push_str(&KEY_EXTENSION);
            }
            Some(_file) => _msk_file = _file.to_string(),
        }
        match arguments.value_of(PK_FILE) {
            None => {
                _pk_file.push_str(&PK_FILE);
                _pk_file.push_str(&DOT);
                _pk_file.push_str(&KEY_EXTENSION);
            }
            Some(_file) => _pk_file = _file.to_string(),
        }
        match _scheme {
            Scheme::YCT14 => {
                let mut _attributes: Vec<String> = Vec::new();
                match arguments.values_of(ATTRIBUTES) {
                    None => {}
                    Some(_attr) => {
                        let _b: Vec<String> = _attr.map(|s| s.to_string()).collect();
                        for _a in _b {
                            for _at in _a.split_whitespace() {
                                _attributes.push(_at.to_string());
                            }
                        }
                    }
                }
                if _attributes.len() > 0 {
                    let (_pk, _msk) = yct14::setup(_attributes);
                    if _json {
                        write_file(
                            Path::new(&_msk_file),
                            serde_json::to_string(&_msk).unwrap(),
                        );
                        write_file(
                            Path::new(&_pk_file),
                            serde_json::to_string(&_pk).unwrap(),
                        );
                    } else {
                        write_file(
                            Path::new(&_msk_file),
                            ser_enc(_msk, MSK_BEGIN, MSK_END)
                        );
                        write_file(
                            Path::new(&_pk_file),
                            ser_enc(_pk, PK_BEGIN, PK_END)
                        );
                    }
                }
                else {
                    return Err(RabeError::new("sorry, yct14 needs attributes at setup()"));
                }
            }
        }
        Ok(())
    }


    fn run_keygen(
        arguments: &ArgMatches,
        _scheme: Scheme,
        _lang: PolicyLanguage,
        _json: bool,
    ) -> Result<(), RabeError> {
        let mut _sk_file = String::from("");
        let mut _ska_file = String::from("");
        let mut _name = String::from("");
        let mut _name_file = String::new();
        let mut _policy: String = String::new();
        let mut _attributes: Vec<String> = Vec::new();
        let mut _msk_file = String::from("");
        let mut _pk_file = String::from("");
        let mut _gp_file = String::from("");
        match arguments.value_of(MSK_FILE) {
            None => {
                _msk_file.push_str(&MSK_FILE);
                _msk_file.push_str(&DOT);
                _msk_file.push_str(&KEY_EXTENSION);
            }
            Some(_file) => {
                _msk_file = _file.to_string();
            }
        }
        match arguments.value_of(PK_FILE) {
            None => {
                _pk_file.push_str(&PK_FILE);
                _pk_file.push_str(&DOT);
                _pk_file.push_str(&KEY_EXTENSION);
            }
            Some(_file) => _pk_file = _file.to_string(),
        }
        match arguments.value_of(SK_FILE) {
            None => {
                _sk_file.push_str(&SK_FILE);
                _sk_file.push_str(&DOT);
                _sk_file.push_str(&KEY_EXTENSION);
            }
            Some(_file) => _sk_file = _file.to_string(),
        }
        match arguments.value_of(POLICY) {
            None => {}
            Some(_pol) => _policy = _pol.to_string(),
        }
        match arguments.value_of(NAME) {
            None => {}
            Some(_n) => {
                _name = _n.to_string();
                _name_file.push_str(&_n.to_string());
                _name_file.push_str(&DOT);
                _name_file.push_str(&KEY_EXTENSION);
            }
        }
        match _scheme {
            Scheme::YCT14 => {
                let mut _pk: yct14::Yct14AbePublicKey;
                let mut _msk: yct14::Yct14AbeMasterKey;
                if _json {
                    _pk = serde_json::from_str(&read_file(Path::new(&_pk_file))).unwrap();
                    _msk = serde_json::from_str(&read_file(Path::new(&_msk_file))).unwrap();
                } else {
                    _pk = match ser_dec(&_pk_file) {
                        Ok(parsed) => match from_slice(&parsed) {
                            Ok(parsed_res) => parsed_res,
                            Err(e) => return Err(e.into())
                        },
                        Err(e) => return Err(e)
                    };
                    _msk = match ser_dec(&_msk_file) {
                        Ok(parsed) => match from_slice(&parsed) {
                            Ok(parsed_res) => parsed_res,
                            Err(e) => return Err(e.into())
                        },
                        Err(e) => return Err(e)
                    };
                }
                println!("generating key with policy {}", &_policy);
                match yct14::keygen(&_pk, &_msk, &_policy, _lang) {
                    Ok(sk) => {
                        if _json {
                            write_file(
                                Path::new(&_sk_file),
                                serde_json::to_string(&sk).unwrap(),
                            );
                        } else {
                            write_file(
                                Path::new(&_sk_file),
                                ser_enc(sk, SK_BEGIN, SK_END)
                            );
                        }
                    },
                    Err(e) => {
                        println!("could not generate key {}", e.to_string());
                    }
                }

            }
        }
        Ok(())
    }

    fn run_encrypt(
        arguments: &ArgMatches,
        _scheme: Scheme,
        _lang: PolicyLanguage,
        _json: bool,
    ) -> Result<(), RabeError> {
        let mut _pk_files: Vec<String> = Vec::new();
        let mut _pk_file = String::from("");
        let mut _gp_file = String::from("");
        let mut _ct_file: String = String::new();
        let mut _pt_file: String = String::new();
        let mut _policy: String = String::new();
        let mut _attributes: Vec<String> = Vec::new();
        match arguments.value_of(PK_FILE) {
            None => {
                _pk_file.push_str(&PK_FILE);
                _pk_file.push_str(&DOT);
                _pk_file.push_str(&KEY_EXTENSION);
                _pk_files.push(_pk_file.clone());
            }
            Some(_file) => {
                let files: Vec<_> = arguments.values_of(PK_FILE).unwrap().collect();
                for file in files {
                    _pk_files.push(file.to_string())
                }
            }
        }
        match arguments.values_of(ATTRIBUTES) {
            None => {}
            Some(_attr) => {
                let _b: Vec<String> = _attr.map(|s| s.to_string()).collect();
                for _a in _b {
                    for _at in _a.split_whitespace() {
                        _attributes.push(_at.to_string());
                    }
                }
            }
        }
        match arguments.value_of(FILE) {
            None => {}
            Some(_file) => {
                _pt_file = _file.to_string();
                _ct_file = _pt_file.to_string();
                _ct_file.push_str(&DOT);
                _ct_file.push_str(&CT_EXTENSION);
            }
        }
        let buffer: Vec<u8> = read_to_vec(Path::new(&_pt_file));
        match _scheme {
            Scheme::YCT14 => {
                let mut _pk: yct14::Yct14AbePublicKey;
                // only one pk is allowed
                if _pk_files.len() == 1 {
                    if _json {
                        _pk = serde_json::from_str(&read_file(Path::new(&_pk_files[0].clone())))
                            .unwrap();
                    } else {
                        _pk = match ser_dec(&_pk_files[0].clone()) {
                            Ok(parsed) => match from_slice(&parsed) {
                                Ok(parsed_res) => parsed_res,
                                Err(e) => return Err(e.into())
                            },
                            Err(e) => return Err(e)
                        };
                    }
                    match yct14::encrypt(&_pk, &_attributes, &buffer) {
                        Ok(ct) => {
                            if _json {
                                let ct = serde_json::to_string(&ct).unwrap();
                                println!("ciphertext: {:?}", &ct);
                                write_file(
                                    Path::new(&_ct_file),
                                    ct,
                                );
                            } else {
                                write_file(
                                    Path::new(&_ct_file),
                                    ser_enc(ct, CT_BEGIN, CT_END)
                                );
                            }
                        },
                        Err(e) => panic!("could not encrypt: {}", e.to_string())
                    }
                } else {
                    return Err(RabeError::new(
                        "sorry, encryption using the LSW Scheme with zero or multiple PKs is not possible. ",
                    ));
                }
            }
        }
        Ok(())
    }

    fn run_decrypt(
        arguments: &ArgMatches,
        _scheme: Scheme,
        _lang: PolicyLanguage,
        _json: bool,
    ) -> Result<(), RabeError> {
        let mut _sk_file = String::from("");
        let mut _gp_file = String::from("");
        let mut _pk_file = String::from("");
        let mut _file: String = String::from("");
        let mut _pt_option: Result<Vec<u8>, RabeError>;
        let mut _policy: String = String::new();
        match arguments.value_of(SK_FILE) {
            None => {
                _sk_file.push_str(&SK_FILE);
                _sk_file.push_str(&DOT);
                _sk_file.push_str(&KEY_EXTENSION);
            }
            Some(_file) => _sk_file = _file.to_string(),
        }
        match arguments.value_of(FILE) {
            None => {}
            Some(x) => _file = x.to_string(),
        }
        match _scheme {
            Scheme::YCT14 => {
                let mut _sk: yct14::Yct14AbeSecretKey;
                let mut _ct: yct14::Yct14AbeCiphertext;
                if _json {
                    _ct = serde_json::from_str(&read_file(Path::new(&_file))).unwrap();
                    _sk = serde_json::from_str(&read_file(Path::new(&_sk_file))).unwrap();
                } else {
                    _sk = match ser_dec(&_sk_file) {
                        Ok(parsed) => match from_slice(&parsed) {
                            Ok(parsed_res) => parsed_res,
                            Err(e) => return Err(e.into())
                        },
                        Err(e) => return Err(e)
                    };
                    _ct = match ser_dec(&_file) {
                        Ok(parsed) => match from_slice(&parsed) {
                            Ok(parsed_res) => parsed_res,
                            Err(e) => return Err(e.into())
                        },
                        Err(e) => return Err(e)
                    };
                }
                _pt_option = yct14::decrypt(&_sk, &_ct);
            }
        }
        match _pt_option {
            Err(e) => {
                return Err(e);
            }
            Ok(_pt_u) => {
                write_from_vec(Path::new(&_file), &_pt_u);
            }
        }
        Ok(())
    }
}

fn ser_enc<T: Serialize>(input: T, head: &str, tail: &str) -> String {
    use deflate::deflate_bytes;
    [
        head,
        &encode(
            &deflate_bytes(
                &to_vec_packed(&input).unwrap()
            )
        ),
        tail
    ].concat()
}
fn ser_dec(file_name: &String) -> Result<Vec<u8>, RabeError> {
    use inflate::inflate_bytes;
    let base64: Vec<u8> = decode(
        &read_raw(
            &read_file(
                Path::new(file_name)
            )
        )
    )?;
    match inflate_bytes(&base64) {
        Ok(bytes) => Ok(bytes),
        Err(e) => Err(RabeError::new(e.to_string().as_str()))
    }

}