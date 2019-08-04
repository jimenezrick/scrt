use std::path::{Path, PathBuf};
use std::{fs, fs::File};
use std::{io, io::Read};

use sodiumoxide;
use structopt::StructOpt;

#[derive(StructOpt, Debug)]
#[structopt(author = "")]
enum Opt {
    #[structopt(name = "gen-key-pair")]
    GenKeyPair {
        #[structopt(short = "f", long = "force")]
        force: bool,
    },

    #[structopt(name = "hash")]
    Hash {
        #[structopt(short = "s", long = "short")]
        short: bool,

        path: PathBuf,
    },

    #[structopt(name = "verify")]
    Verify { path: PathBuf },
}

fn write_new_key_pair(force: bool) -> io::Result<()> {
    if !force && (Path::new("key.pub").exists() || Path::new("key.sec").exists()) {
        eprintln!("Error: can't overwrite existing key pair");
    }
    let (pub_key, sec_key) = sodiumoxide::crypto::sign::gen_keypair();
    fs::write("key.pub", bs58::encode(pub_key).into_string() + "\n")?;
    fs::write("key.sec", bs58::encode(sec_key).into_string() + "\n")?;
    Ok(())
}

fn hash<R: io::Read>(reader: R) -> io::Result<sodiumoxide::crypto::hash::Digest> {
    let buf_size = 8 * 1024;
    let mut buf: Vec<u8> = Vec::with_capacity(buf_size);
    let mut hash_state = sodiumoxide::crypto::hash::State::new();
    let mut limited_reader = reader.take(buf_size as u64);

    loop {
        match limited_reader.read_to_end(&mut buf) {
            Ok(0) => break,
            Ok(_) => {
                hash_state.update(&buf[..]);
                buf.clear();
                limited_reader = limited_reader.into_inner().take(buf_size as u64);
            }
            Err(err) => return Err(err),
        }
    }

    Ok(hash_state.finalize())
}

fn main() -> io::Result<()> {
    sodiumoxide::init().unwrap();

    let opt = Opt::from_args();
    println!("{:?}", opt);

    match opt {
        Opt::GenKeyPair { force } => write_new_key_pair(force)?,
        Opt::Hash { path, short } => {
            let f = File::open(path)?;
            let digest = hash(io::BufReader::new(f))?;
            if short {
                println!("{}", bs58::encode(digest).into_string());
            } else {
                let digest_hex = digest
                    .as_ref()
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<String>();
                println!("{}", digest_hex);
            }
        }
        _ => (),
    }
    Ok(())
}
