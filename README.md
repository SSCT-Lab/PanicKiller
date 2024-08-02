# PanicKiller

## Overview

PanicKiller is a pattern-based automated panic bugs fixing tool. It first locates suspicious expressions based on the backtrace information output by the compiler and the dependency flow analysis of the original program. Then, combining with the semantic information of the errors, it generates a series of patch for each fault location. Finally, it sorts all the patches with verification and matching scores calculation, and outputs the top-5 ranked patches along with the corresponding natural language interpretation.

## Usage

### Build

PanicKiller is built on top of the [Rust project]{https://github.com/rust-lang/rust}. To compile it, follow the instructions provided in the _How  to build and run the compiler Chapter_ of the [Rust Compiler Development Guide](https://rustc-dev-guide.rust-lang.org/building/how-to-build-and-run.html). Building the stage 2 compiler is necessary for compiling PanicKiller. Here are the simplified build instructions:

```shell
python ./x.py build --stage 2
```

### Run

To run PanicKiller, structure your project as follows:

```css
── crate
── src
   ├── backtrace
   └── panic_info.txt
```

Here, backtrace contains the trace output when running the panic case with RUST_BACKTRACE=full, and panic_info.txt holds the error message.

Navigate to the crate directory and set the environment variables:

```shell
export RUSTC=/pathToPanicKiller/build/x86_64-unknown-linux-gnu/stage2/bin/rustc
export RUSTDOC=/pathToPanicKiller/build/x86_64-unknown-linux-gnu/stage2/bin/rustdoc
```

Then, clean the project and generate documentation:

```shell
cargo clean
cargo doc -v
```

This command will typically execute a process with the last command similar to:

```
/pathToRustDoc/rustdoc --edition=2021 --crate-type lib --crate-name crate src/lib.rs -o /pathToCrate/target/doc --cfg 'feature="android-tzdata"' --cfg 'feature="clock"' --cfg 'feature="default"' --cfg 'feature="iana-time-zone"' --cfg 'feature="js-sys"' --cfg 'feature="oldtime"' --cfg 'feature="std"' --cfg 'feature="wasm-bindgen"' --cfg 'feature="wasmbind"' --cfg 'feature="winapi"' --cfg 'feature="windows-targets"' --error-format=json --json=diagnostic-rendered-ansi,artifacts,future-incompat --diagnostic-width=130 -C metadata=d99978fb566a8d1a -L dependency=/pathToCrate/target/debug/deps --extern iana_time_zone=/pathToCrate/target/debug/deps/libiana_time_zone-09090f81caa6c751.rmeta --extern num_traits=/pathToCrate/target/debug/deps/libnum_traits-e8610d3cd080ac83.rmeta --crate-version 0.4.30
```

You should replace rustdoc with tooling in the actual command, like so:

```
/pathToRustDoc/tooling --edition=2021 --crate-type lib --crate-name crate src/lib.rs -o /pathToCrate/target/doc --cfg 'feature="android-tzdata"' --cfg 'feature="clock"' --cfg 'feature="default"' --cfg 'feature="iana-time-zone"' --cfg 'feature="js-sys"' --cfg 'feature="oldtime"' --cfg 'feature="std"' --cfg 'feature="wasm-bindgen"' --cfg 'feature="wasmbind"' --cfg 'feature="winapi"' --cfg 'feature="windows-targets"' --error-format=json --json=diagnostic-rendered-ansi,artifacts,future-incompat --diagnostic-width=130 -C metadata=d99978fb566a8d1a -L dependency=/pathToCrate/target/debug/deps --extern iana_time_zone=/pathToCrate/target/debug/deps/libiana_time_zone-09090f81caa6c751.rmeta --extern num_traits=/pathToCrate/target/debug/deps/libnum_traits-e8610d3cd080ac83.rmeta --crate-version 0.4.30
```

### Output

PanicKiller outputs its results in various files:

- A patches directory: Includes all generated patches.
- log.txt: Contains detailed logs of the operation.
- result.txt: Stores the results of the patches applied.