//! 公開パラメータで長さが決まる、リトルエンディアンの証明形式。
use std::io::{self, Read, Write};

use crate::commitment::Hash;
use crate::fibonacci::Statement;
use crate::field::PRIME;
use crate::proof::{Opening, Proof, Query};

const MAGIC: &[u8; 8] = b"STARK101";

impl Proof {
    /// 先頭に形式識別子、続いて root、最終定数、問い合わせ応答を書き込む。
    pub(crate) fn write(&self, mut output: impl Write) -> io::Result<()> {
        output.write_all(MAGIC)?;
        output.write_all(&self.trace_root)?;
        output.write_all(&self.composition_root)?;
        for root in &self.fri_roots {
            output.write_all(root)?;
        }
        output.write_all(&self.constant.to_le_bytes())?;
        for query in &self.queries {
            for opening in query.openings() {
                output.write_all(&opening.value.to_le_bytes())?;
                for sibling in &opening.path {
                    output.write_all(sibling)?;
                }
            }
        }
        Ok(())
    }

    /// 公開命題から応答数と各認証経路の深さを決め、1個の証明を読み取る。
    pub(crate) fn read(statement: Statement, mut input: impl Read) -> io::Result<Self> {
        if &read_array::<8>(&mut input)? != MAGIC {
            return Err(invalid("証明の形式識別子が一致しません"));
        }
        let trace_root = read_array(&mut input)?;
        let composition_root = read_array(&mut input)?;
        let fri_roots = (0..statement.log_rows)
            .map(|_| read_array(&mut input))
            .collect::<io::Result<Vec<Hash>>>()?;
        let constant = read_field(&mut input)?;

        // 証明ファイルから配列の長さを受け取らず、公開設定から計算する。
        let depth = statement.lde_size().ilog2();
        let mut queries = Vec::with_capacity(statement.queries);
        for _ in 0..statement.queries {
            let trace = [
                read_opening(&mut input, depth)?,
                read_opening(&mut input, depth)?,
                read_opening(&mut input, depth)?,
            ];
            let composition = read_opening(&mut input, depth)?;
            let mut fri = Vec::with_capacity(statement.log_rows as usize);
            for round in 0..statement.log_rows {
                fri.push([
                    read_opening(&mut input, depth - round)?,
                    read_opening(&mut input, depth - round)?,
                ]);
            }
            queries.push(Query {
                trace,
                composition,
                fri,
            });
        }
        if input.read(&mut [0])? != 0 {
            return Err(invalid("証明の末尾に余分なデータがあります"));
        }
        Ok(Self {
            trace_root,
            composition_root,
            fri_roots,
            constant,
            queries,
        })
    }

    /// ファイルに含まれる兄弟ハッシュのバイト数。root と開示値を除く。
    pub(crate) fn authentication_bytes(&self) -> usize {
        self.queries
            .iter()
            .flat_map(Query::openings)
            .map(|opening| opening.path.len() * size_of::<Hash>())
            .sum()
    }
}

impl Query {
    fn openings(&self) -> impl Iterator<Item = &Opening> {
        self.trace
            .iter()
            .chain([&self.composition])
            .chain(self.fri.iter().flatten())
    }
}

fn read_opening(input: &mut impl Read, depth: u32) -> io::Result<Opening> {
    let value = read_field(input)?;
    let path = (0..depth)
        .map(|_| read_array(input))
        .collect::<io::Result<_>>()?;
    Ok(Opening { value, path })
}

fn read_field(input: &mut impl Read) -> io::Result<u64> {
    let value = u64::from_le_bytes(read_array(input)?);
    if value >= PRIME {
        return Err(invalid("有限体の標準表現は p 未満です"));
    }
    Ok(value)
}

fn read_array<const N: usize>(input: &mut impl Read) -> io::Result<[u8; N]> {
    let mut bytes = [0; N];
    input.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
