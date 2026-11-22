# 開発・検証手順

リポジトリのルートから実行する。

```sh
cargo run --quiet
cargo run --quiet --release -- prove target/fibonacci.proof
cargo run --quiet --release -- verify target/fibonacci.proof 2338775057
cargo run --quiet --release -- measure
cargo fmt --check
cargo clippy --offline --all-targets -- -D warnings
cargo test --offline
```

引数なしでトレースを実行。prove は証明ファイルを生成し、verify は別プロセスで公開値を入力する。公開値を 2338775058 に変えた検証と認証経路を改変した証明は拒否される。measure はトレース項数と問い合わせ数を変え、証明全体のバイト数、認証経路のバイト数、検証時間の中央値を CSV 出力する。既定の実測では証明 117136 バイト、認証経路 113664 バイト。計測時間に生成・入出力・デコードを含めない。

整形には rustfmt.toml を使う。公開する関数や型の役割、入出力、前提を日本語の Rustdoc に書く。数式とコードの変数の対応や処理順序の理由は近くのコメントに入れる。README.md の実行例・図解と docs/plan.md の内容を実装に合わせて更新する。構成は `mem:project_overview`。