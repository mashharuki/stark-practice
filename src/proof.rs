//! STARK 101 の証明生成と検証。初期 FRI 層で CP とトレースの次数を検査する。
use crate::commitment::{authenticates, field_challenge, Hash, MerkleTree, Transcript};
use crate::fibonacci::{trace, Constraints, Statement, BLOWUP};
use crate::field::{add, domain, evaluate, interpolate, inv, mul, pow, sub, GENERATOR, HALF};

pub(crate) struct Opening {
    pub(crate) value: u64,
    pub(crate) path: Vec<Hash>,
}

impl Opening {
    // 新しい開示値を、値の配列と Merkle 木から生成する。
    fn new(values: &[u64], tree: &MerkleTree, index: usize) -> Self {
        Self {
            value: values[index],
            path: tree.path(index),
        }
    }

    // 開示値が Merkle 木のルートと一致するか検証する。
    fn check(&self, root: Hash, index: usize, size: usize) -> Result<u64, &'static str> {
        if self.path.len() != size.ilog2() as usize
            || !authenticates(root, index, self.value, &self.path)
        {
            return Err("Merkle 認証に失敗しました");
        }
        Ok(self.value)
    }
}

pub(crate) struct Query {
    pub(crate) trace: [Opening; 3],
    pub(crate) composition: Opening,
    pub(crate) fri: Vec<[Opening; 2]>,
}

pub(crate) struct Proof {
    pub(crate) trace_root: Hash,
    pub(crate) composition_root: Hash,
    pub(crate) fri_roots: Vec<Hash>,
    pub(crate) constant: u64,
    pub(crate) queries: Vec<Query>,
}

/// コミットメントに依存するチャレンジを、証明者と検証者で同じ順序で導く。
fn composition_challenges(transcript: &mut Transcript, root: Hash) -> [u64; 3] {
    transcript.absorb(b"trace root", &root);
    std::array::from_fn(|_| field_challenge(transcript, b"alpha"))
}

fn batching_challenges(transcript: &mut Transcript, root: Hash) -> [u64; 2] {
    transcript.absorb(b"composition root", &root);
    std::array::from_fn(|_| field_challenge(transcript, b"gamma"))
}

fn fold_challenge(transcript: &mut Transcript, root: Hash) -> u64 {
    transcript.absorb(b"fri root", &root);
    field_challenge(transcript, b"beta")
}

fn batch(x: u64, trace_value: u64, cp: u64, [gamma0, gamma1]: [u64; 2]) -> u64 {
    // f と X*f の両方の次数が rows-1 以下なら、f の次数は rows-2 以下。
    // 既に固定した CP、f、X*f を乱数でまとめ、同じ FRI で検査する。
    add(cp, mul(add(gamma0, mul(gamma1, x)), trace_value))
}

fn fold(x: u64, at_x: u64, at_negative_x: u64, beta: u64) -> u64 {
    // P(X)=E(X²)+X*O(X²)。和と差から E(x²) と O(x²) を復元する。
    let even = mul(HALF, add(at_x, at_negative_x));
    let odd = mul(mul(HALF, inv(x)), sub(at_x, at_negative_x));
    add(even, mul(beta, odd))
}

/// 第2項を知る証明者が、公開された末尾に対する証明を組み立てる。
pub(crate) fn prove(statement: Statement, witness: u64) -> Result<Proof, &'static str> {
    let trace = trace(statement.rows(), witness);
    if trace.last() != Some(&statement.end) {
        return Err("第2項から公開された末尾に到達しません");
    }

    let nodes = domain(trace.len(), 1, statement.g());
    let coefficients = interpolate(&nodes, &trace);
    let size = statement.lde_size();
    // trace[i]=f(g^i)。拡張台は 5*<omega> で、制約の分母に現れる根を含まない。
    let points = domain(size, GENERATOR, statement.omega());
    let lde: Vec<_> = points
        .iter()
        .map(|&x| evaluate(&nodes, &coefficients, x))
        .collect();
    let trace_tree = MerkleTree::new(&lde);
    let trace_root = trace_tree.root();

    let mut transcript = statement.transcript();
    let alpha = composition_challenges(&mut transcript, trace_root);
    let constraints = Constraints::new(statement);
    let cp: Vec<_> = points
        .iter()
        .enumerate()
        .map(|(index, &x)| {
            let values = std::array::from_fn(|i| lde[(index + i * BLOWUP) % size]);
            constraints.composition(x, values, alpha)
        })
        .collect();
    let cp_tree = MerkleTree::new(&cp);
    let composition_root = cp_tree.root();
    let gamma = batching_challenges(&mut transcript, composition_root);

    let mut evaluations: Vec<_> = (0..size)
        .map(|i| batch(points[i], lde[i], cp[i], gamma))
        .collect();
    let mut fri_layers = Vec::new();
    let mut offset = GENERATOR;
    let mut omega = statement.omega();
    for _ in 0..statement.log_rows {
        let tree = MerkleTree::new(&evaluations);
        let beta = fold_challenge(&mut transcript, tree.root());
        let half = evaluations.len() / 2;
        let next = domain(half, offset, omega)
            .into_iter()
            .enumerate()
            .map(|(i, x)| {
                // 自然順の乗法領域では後半の点が前半の点の -x に対応する。
                fold(x, evaluations[i], evaluations[i + half], beta)
            })
            .collect();
        fri_layers.push((evaluations, tree));
        evaluations = next;
        offset = mul(offset, offset);
        omega = mul(omega, omega);
    }
    let constant = evaluations[0];
    if evaluations.iter().any(|&value| value != constant) {
        return Err("FRI の最終層が定数になりませんでした");
    }
    transcript.absorb(b"final constant", &constant.to_le_bytes());

    // 値の開示位置は全ての層と最終定数を固定してから決める。
    let queries = (0..statement.queries)
        .map(|_| {
            let mut index = transcript.sample(b"query", size as u64) as usize;
            let trace = std::array::from_fn(|i| {
                Opening::new(&lde, &trace_tree, (index + i * BLOWUP) % size)
            });
            let composition = Opening::new(&cp, &cp_tree, index);
            let fri = fri_layers
                .iter()
                .map(|(values, tree)| {
                    let half = values.len() / 2;
                    index %= half;
                    [
                        Opening::new(values, tree, index),
                        Opening::new(values, tree, index + half),
                    ]
                })
                .collect();
            Query {
                trace,
                composition,
                fri,
            }
        })
        .collect();

    Ok(Proof {
        trace_root,
        composition_root,
        fri_roots: fri_layers.iter().map(|(_, tree)| tree.root()).collect(),
        constant,
        queries,
    })
}

/// 公開命題と証明から認証経路と問い合わせ先の代数的な関係を検証する。
pub(crate) fn verify(statement: Statement, proof: &Proof) -> Result<(), &'static str> {
    let rounds = statement.log_rows as usize;
    if proof.fri_roots.len() != rounds || proof.queries.len() != statement.queries {
        return Err("証明の構造が公開パラメータと一致しません");
    }
    let size = statement.lde_size();
    let mut transcript = statement.transcript();
    let alpha = composition_challenges(&mut transcript, proof.trace_root);
    let gamma = batching_challenges(&mut transcript, proof.composition_root);
    let betas: Vec<_> = proof
        .fri_roots
        .iter()
        .map(|&root| fold_challenge(&mut transcript, root))
        .collect();
    transcript.absorb(b"final constant", &proof.constant.to_le_bytes());

    let constraints = Constraints::new(statement);
    for query in &proof.queries {
        if query.fri.len() != rounds {
            return Err("FRI の層数が一致しません");
        }
        let mut index = transcript.sample(b"query", size as u64) as usize;
        let mut trace_values = [0; 3];
        for (i, opening) in query.trace.iter().enumerate() {
            trace_values[i] = opening.check(proof.trace_root, (index + i * BLOWUP) % size, size)?;
        }
        let x = mul(GENERATOR, pow(statement.omega(), index as u64));
        let cp = query
            .composition
            .check(proof.composition_root, index, size)?;
        if cp != constraints.composition(x, trace_values, alpha) {
            return Err("合成多項式とトレースの制約が一致しません");
        }
        let mut expected = batch(x, trace_values[0], cp, gamma);
        let mut layer_size = size;
        let mut offset = GENERATOR;
        let mut omega = statement.omega();
        for ((pair, &root), &beta) in query.fri.iter().zip(&proof.fri_roots).zip(&betas) {
            let half = layer_size / 2;
            let left = index % half;
            let a = pair[0].check(root, left, layer_size)?;
            let b = pair[1].check(root, left + half, layer_size)?;
            // 前層の折り畳み結果は、今回のペアのうち問い合わせ位置に対応する値。
            let opened = if index < half { a } else { b };
            if opened != expected {
                return Err("FRI の開示値が前段の値と一致しません");
            }
            let x = mul(offset, pow(omega, left as u64));
            expected = fold(x, a, b, beta);
            index = left;
            layer_size = half;
            offset = mul(offset, offset);
            omega = mul(omega, omega);
        }
        if expected != proof.constant {
            return Err("FRI の最終定数が一致しません");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fibonacci::transition;
    use crate::field::PRIME;

    #[test]
    fn interpolation_and_transition_roots() {
        let values = trace(16, 3);
        let statement = Statement::new(4, values[14], 4).unwrap();
        let nodes = domain(values.len(), 1, statement.g());
        let coefficients = interpolate(&nodes, &values);
        let recovered: Vec<_> = nodes
            .iter()
            .map(|&x| evaluate(&nodes, &coefficients, x))
            .collect();
        assert_eq!(recovered, values);
        // 分子が全ての異なる根でゼロなら、根に対応する因子の積で割り切れる。
        assert!(recovered
            .windows(3)
            .all(|w| transition(w[0], w[1], w[2]) == 0));
        let mut altered = recovered;
        altered[4] = add(altered[4], 1);
        assert_ne!(transition(altered[2], altered[3], altered[4]), 0);
    }

    #[test]
    fn merkle_authenticates_each_lde_leaf() {
        let nodes = [1, 2];
        let coefficients = interpolate(&nodes, &[5, 7]);
        let values: Vec<_> = (10..42)
            .map(|x| evaluate(&nodes, &coefficients, x))
            .collect();
        let tree = MerkleTree::new(&values);
        for (i, &value) in values.iter().enumerate() {
            let path = tree.path(i);
            assert!(authenticates(tree.root(), i, value, &path));
            assert!(!authenticates(tree.root(), i, add(value, 1), &path));
        }
    }

    #[test]
    fn folding_matches_coefficient_formula() {
        let p = |x| {
            add(
                add(3, mul(5, x)),
                add(mul(7, pow(x, 2)), mul(11, pow(x, 3))),
            )
        };
        let x = 9;
        let beta = 13;
        assert_eq!(
            fold(x, p(x), p(PRIME - x), beta),
            add(
                add(3, mul(7, pow(x, 2))),
                mul(beta, add(5, mul(11, pow(x, 2))))
            )
        );
    }
}
