//! FibonacciSq の公開命題と AIR（境界制約・遷移制約）。
use crate::commitment::Transcript;
use crate::field::{add, inv, mul, pow, sub, GENERATOR, PRIME};

pub(crate) const BLOWUP: usize = 8;
pub(crate) const DEFAULT_LOG_ROWS: u32 = 10;
pub(crate) const DEFAULT_QUERIES: usize = 16;
pub(crate) const WITNESS: u64 = 3_141_592;
pub(crate) const EXPECTED: u64 = 2_338_775_057;

#[derive(Clone, Copy)]
pub(crate) struct Statement {
    pub(crate) log_rows: u32,
    pub(crate) end: u64,
    pub(crate) queries: usize,
}

impl Statement {
    /// 台のサイズは 2^log_rows。トレースは最後の1点を除く。
    pub(crate) fn new(log_rows: u32, end: u64, queries: usize) -> Result<Self, &'static str> {
        if !(2..=DEFAULT_LOG_ROWS).contains(&log_rows)
            || end >= PRIME
            || !(1..=64).contains(&queries)
        {
            return Err("log_rows は 2〜10、末尾は 0 以上 p 未満、問い合わせ数は 1〜64");
        }
        Ok(Self {
            log_rows,
            end,
            queries,
        })
    }

    pub(crate) fn rows(self) -> usize {
        1 << self.log_rows
    }

    pub(crate) fn lde_size(self) -> usize {
        BLOWUP * self.rows()
    }

    pub(crate) fn omega(self) -> u64 {
        pow(GENERATOR, (PRIME - 1) / self.lde_size() as u64)
    }

    pub(crate) fn g(self) -> u64 {
        pow(self.omega(), BLOWUP as u64)
    }

    /// 公開された値を全コミットメントとチャレンジに結び付ける。
    pub(crate) fn transcript(self) -> Transcript {
        let mut transcript = Transcript::new();
        transcript.absorb(b"log rows", &self.log_rows.to_le_bytes());
        transcript.absorb(b"last value", &self.end.to_le_bytes());
        transcript.absorb(b"query count", &(self.queries as u64).to_le_bytes());
        transcript
    }
}

/// 初項1と第2項を使い、rows - 1 個の有限体要素を計算する。
pub(crate) fn trace(rows: usize, second: u64) -> Vec<u64> {
    let mut trace = vec![1, second % PRIME];
    for i in 2..rows - 1 {
        let a = trace[i - 2];
        let b = trace[i - 1];
        trace.push(add(mul(a, a), mul(b, b)));
    }
    trace
}

pub(crate) fn transition(a: u64, b: u64, c: u64) -> u64 {
    sub(c, add(mul(a, a), mul(b, b)))
}

pub(crate) struct Constraints {
    rows: usize,
    end: u64,
    last_point: u64,
    omitted_transition_points: [u64; 3],
}

impl Constraints {
    pub(crate) fn new(statement: Statement) -> Self {
        let rows = statement.rows();
        let g = statement.g();
        Self {
            rows,
            end: statement.end,
            last_point: pow(g, (rows - 2) as u64),
            omitted_transition_points: [rows - 3, rows - 2, rows - 1].map(|i| pow(g, i as u64)),
        }
    }

    /// LDE台上の x で3つの商を評価し、公開乱数 alpha で合成する。
    pub(crate) fn composition(&self, x: u64, [a, b, c]: [u64; 3], alpha: [u64; 3]) -> u64 {
        let first = mul(sub(a, 1), inv(sub(x, 1)));
        let last = mul(sub(a, self.end), inv(sub(x, self.last_point)));
        // 遷移は i = 0..=rows-4。Z(X) は X^rows-1 から末尾3因子を除いた積。
        // LDE台はトレースの部分群と交わらないため、分母を安全に反転できる。
        let omitted = self
            .omitted_transition_points
            .iter()
            .fold(1, |product, &point| mul(product, sub(x, point)));
        let inverse_vanishing = mul(omitted, inv(sub(pow(x, self.rows as u64), 1)));
        let step = mul(transition(a, b, c), inverse_vanishing);
        [first, last, step]
            .into_iter()
            .zip(alpha)
            .fold(0, |sum, (quotient, weight)| add(sum, mul(quotient, weight)))
    }
}
