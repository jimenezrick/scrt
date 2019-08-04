use std::fs::File;
use std::io;
use std::io::Read;
use std::path::PathBuf;

use sodiumoxide;
use structopt::StructOpt;

#[derive(StructOpt, Debug)]
#[structopt(author = "")]
enum Opt {
    #[structopt(name = "hash")]
    Hash { path: PathBuf },
    #[structopt(name = "verify")]
    Verify { path: PathBuf },
}

fn hash<R: io::Read>(reader: R) -> io::Result<sodiumoxide::crypto::hash::Digest> {
    let buf_size = 4096 * 4;
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
        Opt::Hash { path } => {
            let f = File::open(path)?;
            let digest = hash(io::BufReader::new(f))?;

            println!("{:x?}", digest.as_ref());
        }
        _ => (),
    }
    Ok(())
}
