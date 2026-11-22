//! 評価表の Merkle コミットメントと Fiat–Shamir 履歴。
use sha2::{Digest, Sha256};

use crate::field::PRIME;

pub(crate) type Hash = [u8; 32];

fn hash(parts: &[&[u8]]) -> Hash {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn leaf(value: u64) -> Hash {
    // 葉と内部ノードをタグで区別してハッシュする。
    hash(&[b"leaf", &value.to_le_bytes()])
}

fn branch(left: &Hash, right: &Hash) -> Hash {
    hash(&[b"node", left, right])
}

/// 2のべき乗個の評価値を固定し、任意の葉の認証経路を作る木。
pub(crate) struct MerkleTree(Vec<Vec<Hash>>);

impl MerkleTree {
    pub(crate) fn new(values: &[u64]) -> Self {
        assert!(values.len().is_power_of_two());
        let mut levels = vec![values.iter().copied().map(leaf).collect::<Vec<_>>()];
        while levels.last().unwrap().len() > 1 {
            let parents = levels
                .last()
                .unwrap()
                .chunks_exact(2)
                .map(|pair| branch(&pair[0], &pair[1]))
                .collect();
            levels.push(parents);
        }
        Self(levels)
    }

    pub(crate) fn root(&self) -> Hash {
        self.0.last().unwrap()[0]
    }

    pub(crate) fn path(&self, mut index: usize) -> Vec<Hash> {
        self.0[..self.0.len() - 1]
            .iter()
            .map(|level| {
                let sibling = level[index ^ 1];
                index /= 2;
                sibling
            })
            .collect()
    }
}

/// 葉から兄弟ハッシュを順に合成し、指定位置の値が root に対応するかを調べる。
pub(crate) fn authenticates(root: Hash, mut index: usize, value: u64, path: &[Hash]) -> bool {
    let mut node = leaf(value);
    for sibling in path {
        node = if index & 1 == 0 {
            branch(&node, sibling)
        } else {
            branch(sibling, &node)
        };
        index /= 2;
    }
    index == 0 && node == root
}

/// 公開命題とメッセージを順に吸収し、証明者と検証者で同じ乱数を導く。
pub(crate) struct Transcript(Hash);

impl Transcript {
    pub(crate) fn new() -> Self {
        Self(hash(&[b"stark-practice-v1"]))
    }

    pub(crate) fn absorb(&mut self, label: &[u8], bytes: &[u8]) {
        self.0 = hash(&[
            b"absorb",
            &self.0,
            &(label.len() as u64).to_le_bytes(),
            label,
            bytes,
        ]);
    }

    pub(crate) fn sample(&mut self, label: &[u8], modulus: u64) -> u64 {
        // 上端の余りを棄却し、剰余による偏りを除く。棄却しても状態は進む。
        let threshold = modulus.wrapping_neg() % modulus;
        loop {
            self.absorb(b"sample", label);
            let candidate = u64::from_le_bytes(self.0[..8].try_into().unwrap());
            if candidate >= threshold {
                return candidate % modulus;
            }
        }
    }
}

pub(crate) fn field_challenge(transcript: &mut Transcript, label: &[u8]) -> u64 {
    transcript.sample(label, PRIME)
}
