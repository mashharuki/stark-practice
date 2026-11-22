//! STARK 101 の有限体と Newton 補間。

// 3_221_225_473 は 2^31 - 1 より大きく、2^32 より小さい素数であり、
// 2^32 の剰余演算を u64 で安全に行える。
pub(crate) const PRIME: u64 = 3_221_225_473;
pub(crate) const GENERATOR: u64 = 5;
// 2^31 - 1 より大きい素数の半分は u32 に収まる。
pub(crate) const HALF: u64 = PRIME.div_ceil(2);

// 足し算
pub(crate) fn add(a: u64, b: u64) -> u64 {
    (a + b) % PRIME
}

// 引き算
pub(crate) fn sub(a: u64, b: u64) -> u64 {
    (a + PRIME - b) % PRIME
}

// 掛け算
pub(crate) fn mul(a: u64, b: u64) -> u64 {
    // 正規化された2要素の積は u64 に収まる。和を取る前に剰余を取る。
    a * b % PRIME
}

// 累乗
pub(crate) fn pow(mut base: u64, mut exponent: u64) -> u64 {
    let mut result = 1;
    while exponent != 0 {
        if exponent % 2 == 1 {
            result = mul(result, base);
        }
        base = mul(base, base);
        exponent /= 2;
    }
    result
}

/// 逆元を求める。
pub(crate) fn inv(value: u64) -> u64 {
    assert_ne!(value, 0);
    pow(value, PRIME - 2)
}

/// 互いに異なる等比数列の点 offset * step^i を size 個生成する。
pub(crate) fn domain(size: usize, offset: u64, step: u64) -> Vec<u64> {
    std::iter::successors(Some(offset), |&x| Some(mul(x, step)))
        .take(size)
        .collect()
}

/// 異なる点 nodes の評価値から Newton 基底の係数を求める。
pub(crate) fn interpolate(nodes: &[u64], values: &[u64]) -> Vec<u64> {
    let mut coefficients = values.to_vec();
    // 後ろから更新し、前段の差商 coefficients[i - 1] を上書きせずに使う。
    for order in 1..nodes.len() {
        for i in (order..nodes.len()).rev() {
            coefficients[i] = mul(
                sub(coefficients[i], coefficients[i - 1]),
                inv(sub(nodes[i], nodes[i - order])),
            );
        }
    }
    coefficients
}

/// 補間で使った nodes の順に Newton 形式の多項式を評価する。
pub(crate) fn evaluate(nodes: &[u64], coefficients: &[u64], x: u64) -> u64 {
    let mut value = *coefficients.last().unwrap();
    for i in (0..coefficients.len() - 1).rev() {
        value = add(coefficients[i], mul(sub(x, nodes[i]), value));
    }
    value
}
