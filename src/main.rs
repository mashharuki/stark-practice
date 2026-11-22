#![cfg_attr(feature = "zk", recursion_limit = "256")]

mod commitment;
mod encoding;
mod fibonacci;
mod field;
mod proof;
#[cfg(feature = "zk")]
mod zk;

use std::error::Error;
use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::process::ExitCode;
use std::time::Instant;

use fibonacci::{trace, Statement, DEFAULT_LOG_ROWS, DEFAULT_QUERIES, EXPECTED, WITNESS};
use proof::{prove, verify, Proof};

const USAGE: &str = "使い方\n  stark-practice\n  stark-practice prove <証明ファイル>\n  stark-practice verify <証明ファイル> <公開された末尾>\n  stark-practice measure";

fn main() -> ExitCode {
    // ファイル名にシステム固有の文字が含まれていても、そのまま開けるようにする。
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &[std::ffi::OsString]) -> Result<(), Box<dyn Error>> {
    match args {
        [] => {
            let trace = trace(1 << DEFAULT_LOG_ROWS, WITNESS);
            let last_index = trace.len() - 1;
            println!("先頭3項 = {:?}", &trace[..3]);
            println!("a[{last_index}] = {}", trace[last_index]);
            assert_eq!(trace[last_index], EXPECTED);
        }
        [command] if command == "--help" || command == "-h" => {
            println!("{USAGE}");
            #[cfg(feature = "zk")]
            println!("  stark-practice prove-zk <証明ファイル> <公開された末尾> （第2項は標準入力）\n  stark-practice verify-zk <証明ファイル> <公開された末尾>");
        }
        [command, path] if command == "prove" => {
            let statement = Statement::new(DEFAULT_LOG_ROWS, EXPECTED, DEFAULT_QUERIES)?;
            let proof = prove(statement, WITNESS)?;
            let mut writer = BufWriter::new(File::create(path)?);
            proof.write(&mut writer)?;
            writer.flush()?;
            println!("証明を生成しました。公開された末尾 = {}", statement.end);
        }
        [command, path, end] if command == "verify" => {
            let end = end
                .to_str()
                .ok_or("末尾を10進数で指定してください")?
                .parse()?;
            let statement = Statement::new(DEFAULT_LOG_ROWS, end, DEFAULT_QUERIES)?;
            let proof = Proof::read(statement, BufReader::new(File::open(path)?))?;
            verify(statement, &proof)?;
            println!("検証に成功しました。公開された末尾 = {end}");
        }
        #[cfg(feature = "zk")]
        [command, path, end] if command == "prove-zk" => {
            let end = end
                .to_str()
                .ok_or("末尾を10進数で指定してください")?
                .parse()?;
            // 秘密値をコマンドライン引数に含めず、標準入力から読み取る。
            let mut line = String::new();
            std::io::stdin().read_line(&mut line)?;
            let second = line.trim().parse()?;
            let proof = zk::prove(second, end)?;
            let mut writer = BufWriter::new(File::create(path)?);
            zk::write(&proof, &mut writer)?;
            writer.flush()?;
            println!("ゼロ知識証明を生成しました。公開された末尾 = {end}");
        }
        #[cfg(feature = "zk")]
        [command, path, end] if command == "verify-zk" => {
            let end = end
                .to_str()
                .ok_or("末尾を10進数で指定してください")?
                .parse()?;
            let proof = zk::read(File::open(path)?)?;
            zk::verify(end, &proof)?;
            println!("ゼロ知識証明の検証に成功しました。公開された末尾 = {end}");
        }
        [command] if command == "measure" => measure()?,
        _ => return Err(USAGE.into()),
    }
    Ok(())
}

fn measure() -> Result<(), Box<dyn Error>> {
    println!("trace_terms,queries,proof_bytes,authentication_bytes,verify_median_us");
    for (log_rows, queries) in [(6, 16), (8, 16), (10, 16), (10, 4), (10, 32)] {
        let rows = 1 << log_rows;
        let end = trace(rows, WITNESS)[rows - 2];
        let statement = Statement::new(log_rows, end, queries)?;
        let proof = prove(statement, WITNESS)?;
        let mut encoded = Vec::new();
        proof.write(&mut encoded)?;
        // 証明全体はシリアライズ後の長さ。検証時間からは生成・入出力・デコードを除く。
        let mut durations = Vec::new();
        for _ in 0..9 {
            let start = Instant::now();
            verify(statement, &proof)?;
            durations.push(start.elapsed().as_micros());
        }
        durations.sort_unstable();
        println!(
            "{},{},{},{},{}",
            rows - 1,
            queries,
            encoded.len(),
            proof.authentication_bytes(),
            durations[durations.len() / 2]
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::{add, PRIME};

    #[test]
    fn agrees_with_the_workshop_examples() {
        let rows = 1 << DEFAULT_LOG_ROWS;
        assert_eq!(&trace(rows, 3)[..5], &[1, 3, 10, 109, 11981]);
        assert_eq!(trace(rows, WITNESS)[rows - 2], EXPECTED);
    }

    #[test]
    fn proof_round_trips_and_rejects_tampering() {
        let end = trace(16, WITNESS)[14];
        let statement = Statement::new(4, end, 8).unwrap();
        assert!(prove(statement, 0).is_err());
        let mut bytes = Vec::new();
        prove(statement, WITNESS)
            .unwrap()
            .write(&mut bytes)
            .unwrap();
        let mut proof = Proof::read(statement, bytes.as_slice()).unwrap();
        assert!(verify(statement, &proof).is_ok());
        assert!(verify(Statement::new(4, add(end, 1), 8).unwrap(), &proof).is_err());
        assert!(Proof::read(statement, &bytes[..bytes.len() - 1]).is_err());

        proof.constant = add(proof.constant, 1);
        assert!(verify(statement, &proof).is_err());
        proof.constant = crate::field::sub(proof.constant, 1);
        proof.queries[0].trace[0].path[0][0] ^= 1;
        assert!(verify(statement, &proof).is_err());

        let constant_offset = 8 + 32 * (2 + statement.log_rows as usize);
        let mut noncanonical = bytes.clone();
        noncanonical[constant_offset..constant_offset + 8].copy_from_slice(&PRIME.to_le_bytes());
        assert!(Proof::read(statement, noncanonical.as_slice()).is_err());
        bytes.push(0);
        assert!(Proof::read(statement, bytes.as_slice()).is_err());
    }
}
