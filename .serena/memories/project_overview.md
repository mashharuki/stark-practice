# stark-practice

STARK 101 (StarkWare) を題材にした Rust 2021 の学習用 CLI。FibonacciSq のトレース生成、補間と LDE、SHA-256 Merkle コミットメント、多項式制約、FRI、別プロセスでの証明検証、計測まで実装済み。README.md に日本語の説明、Mermaid 図、実行例、実測値がある。docs/plan.md に段階別の完了条件と日本語のコメント方針がある。

- src/main.rs は既定のデモ、prove / verify / measure を扱う。
- src/fibonacci.rs は公開命題、FibonacciSq、境界・遷移制約。src/field.rs は有限体演算と Newton 補間。
- src/commitment.rs は Merkle 木と Fiat–Shamir。src/proof.rs は CP、初期 FRI 層への束ね方、折り畳みと検証。FRI に CP + γ₀f + γ₁Xf を渡してトレースの次数も検査する。
- src/encoding.rs は公開パラメータから構造が決まるバイナリ証明の入出力。

既定は N=1024 の台に 1023 項、LDE 8192 点、16 問い合わせ。第2項のデモ値は 3141592、公開された末尾 a[1022] は 2338775057。ゼロ知識性の追加は議論まで。補間後の f + ZR（Z はトレースの点で消える多項式、R は証明ごとの乱数）が検討の出発点。実際に追加する際は CP / FRI の次数上限と、開示値・最終出力を含む証明全体の情報漏えいを検討する。現状は学習用でゼロ知識化や実運用向けの安全性評価は未実装。

開発・検証手順は `mem:development_workflow`。