//! 同じ公開命題を Triton VM の zk-STARK で証明する。
use std::io::{self, Read, Write};

use triton_vm::prelude::*;
use triton_vm::proof_item::ProofItem;
use triton_vm::proof_stream::ProofStream;

use crate::fibonacci::{trace, DEFAULT_LOG_ROWS};
use crate::field::PRIME;

const GOLDILOCKS: u64 = 0xffff_ffff_0000_0001;
const ROWS: usize = 1 << DEFAULT_LOG_ROWS;
const STEPS: usize = ROWS - 3;
const HEIGHT: usize = 1 << 17;
const MAGIC: &[u8; 8] = b"FIBZK001";
const MAX_PROOF_BYTES: u64 = 8 * 1024 * 1024;

fn program() -> Program {
    triton_program!(
        divine 1
        call canonical
        dup 0 call square_mod
        push 1 swap 1
        push {STEPS}
        call fibonacci
        pop 1 pop 2
        write_io 1
        // u32 テーブルの高さは秘密値に依存し得る。公開の固定回数だけ
        // ループし、全入力の padded height を同じ 2^17 に揃える。
        push 17000 call pad pop 1
        halt

        fibonacci:                  // 前回の b、a² mod p、b² mod p、残り回数
            dup 2 dup 2 add        // 2つの剰余の和は 0〜2p-2
            addi {-i64::try_from(PRIME).unwrap()}
            dup 0 split pop 1      // 差が負なら Goldilocks で折り返し、上位語が非ゼロ
            push 0 eq push 0 eq
            push {PRIME} mul add   // 負のときだけ p を足し戻す。結果は c
            dup 0 call square_mod  // c、c² mod p
            pick 5 pop 1
            pick 4 pop 1
            pick 1 place 3
            swap 1 addi -1         // c、b² mod p、c² mod p、残り回数 - 1
            dup 0 skiz recurse
            return

        square_mod:                 // 入力 x は 0 <= x < p
            dup 0 mul
            divine 1 call canonical // 剰余 r
            divine 1 call canonical // 商 q
            // x² と q*p+r は p² 未満。p² は Goldilocks の法より小さいので、
            // VM での等式は整数としても成立し、r<p によって剰余が一意に決まる。
            push {PRIME} mul dup 1 add
            dup 2 eq assert
            swap 1 pop 1
            return

        canonical:                  // x を残し、u32 かつ x<p と検査
            push {PRIME} dup 1 lt assert
            return

        pad:
            addi -1 dup 0 skiz recurse
            return
    )
}

fn witness_tokens(second: u64) -> Vec<BFieldElement> {
    let values = trace(ROWS, second);
    let mut tokens = vec![BFieldElement::new(second)];
    for &x in &values[1..] {
        let square = x * x;
        // VM で r、q の順に読み取り、両方を制約で検査する。
        tokens.extend([
            BFieldElement::new(square % PRIME),
            BFieldElement::new(square / PRIME),
        ]);
    }
    tokens
}

fn claim(program: &Program, end: u64) -> Claim {
    Claim::about_program(program).with_output(vec![BFieldElement::new(end)])
}

/// 秘密の第2項から固定プログラムの zk-STARK を生成する。
pub(crate) fn prove(second: u64, end: u64) -> Result<Proof, &'static str> {
    if second >= PRIME || end >= PRIME {
        return Err("第2項と公開値は 0 以上 p 未満で指定してください");
    }
    let program = program();
    let claim = claim(&program, end);
    let (aet, output) = VM::trace_execution(
        program,
        PublicInput::default(),
        NonDeterminism::new(witness_tokens(second)),
    )
    .map_err(|_| "FibonacciSq の仮想マシン実行に失敗しました")?;
    if output != claim.output {
        return Err("第2項から指定された公開値に到達しません");
    }
    if aet.padded_height() != HEIGHT {
        return Err("公開のトレース高さと一致しません");
    }
    Stark::default()
        .prove(&claim, &aet)
        .map_err(|_| "ゼロ知識証明の生成に失敗しました")
}

/// 手元の固定プログラムと指定した公開値を使い、証明を検証する。
pub(crate) fn verify(end: u64, proof: &Proof) -> Result<(), &'static str> {
    if end >= PRIME {
        return Err("公開値は 0 以上 p 未満で指定してください");
    }
    let stream = ProofStream::try_from(proof).map_err(|_| "ゼロ知識証明の構造が不正です")?;
    // ファイル由来の指数をシフトする前に、固定した公開値と比較する。
    if !matches!(stream.items.first(), Some(ProofItem::Log2PaddedHeight(log)) if *log == HEIGHT.ilog2())
    {
        return Err("公開のトレース高さと一致しません");
    }
    drop(stream);
    Stark::default()
        .verify(&claim(&program(), end), proof)
        .map_err(|_| "ゼロ知識証明の検証に失敗しました")
}

/// 形式識別子と、Triton VM の証明に含まれる有限体要素を保存する。
pub(crate) fn write(proof: &Proof, mut output: impl Write) -> io::Result<()> {
    output.write_all(MAGIC)?;
    for value in &proof.0 {
        output.write_all(&value.value().to_le_bytes())?;
    }
    Ok(())
}

/// 証明ファイルのサイズを制限し、正規表現の有限体要素だけを読む。
pub(crate) fn read(input: impl Read) -> io::Result<Proof> {
    let mut bytes = Vec::new();
    input.take(MAX_PROOF_BYTES + 1).read_to_end(&mut bytes)?;
    if !bytes.starts_with(MAGIC)
        || bytes.len() as u64 > MAX_PROOF_BYTES
        || bytes.len() <= MAGIC.len()
        || bytes.len() & 7 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ゼロ知識証明の形式または長さが不正です",
        ));
    }
    let values = bytes[MAGIC.len()..]
        .chunks_exact(8)
        .map(|word| {
            let value = u64::from_le_bytes(word.try_into().unwrap());
            if value >= GOLDILOCKS {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "有限体要素が範囲外です",
                ));
            }
            Ok(BFieldElement::new(value))
        })
        .collect::<io::Result<_>>()?;
    Ok(Proof(values))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fibonacci::{EXPECTED, WITNESS};

    fn execute(tokens: Vec<BFieldElement>) -> (usize, u64) {
        let (aet, output) = VM::trace_execution(
            program(),
            PublicInput::default(),
            NonDeterminism::new(tokens),
        )
        .unwrap();
        assert_eq!(output.len(), 1);
        (aet.padded_height(), output[0].value())
    }

    #[test]
    fn guest_matches_fibonacci_sq_and_uses_fixed_height() {
        assert_eq!(execute(witness_tokens(WITNESS)), (HEIGHT, EXPECTED));
        for second in [0, 1, 23, PRIME - 1] {
            assert_eq!(
                execute(witness_tokens(second)),
                (HEIGHT, trace(ROWS, second)[ROWS - 2])
            );
        }
    }

    #[test]
    fn guest_rejects_false_division_and_noncanonical_witness() {
        let mut tokens = witness_tokens(WITNESS);
        tokens[2] = BFieldElement::new(tokens[2].value() + 1);
        assert!(VM::run(
            program(),
            PublicInput::default(),
            NonDeterminism::new(tokens)
        )
        .is_err());
        let tokens = vec![BFieldElement::new(PRIME)];
        assert!(VM::run(
            program(),
            PublicInput::default(),
            NonDeterminism::new(tokens)
        )
        .is_err());
    }

    #[test]
    fn verification_rejects_an_out_of_range_height() {
        let mut stream = ProofStream::new();
        stream.enqueue(ProofItem::Log2PaddedHeight(u32::MAX));
        assert!(verify(EXPECTED, &Proof::from(stream)).is_err());
    }

    #[test]
    fn read_rejects_other_formats_and_noncanonical_words() {
        assert!(read(b"STARK101".as_slice()).is_err());
        let bad = [MAGIC.as_slice(), &GOLDILOCKS.to_le_bytes()].concat();
        assert!(read(bad.as_slice()).is_err());
    }
}
