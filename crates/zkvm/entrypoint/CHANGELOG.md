# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0](https://github.com/succinctlabs/sp1/compare/sp1-zkvm-v1.0.1...sp1-zkvm-v1.1.0) - 2024-08-02

### Added
- update tg ([#1214](https://github.com/succinctlabs/sp1/pull/1214))

### Fixed
- mutable static ref warning in halt syscall ([#1217](https://github.com/succinctlabs/sp1/pull/1217))

## [1.0.0-rc.1](https://github.com/succinctlabs/sp1/compare/sp1-zkvm-v1.0.0-rc.1...sp1-zkvm-v1.0.0-rc.1) - 2024-07-19

### Added

- publish sp1 to crates.io ([#1052](https://github.com/succinctlabs/sp1/pull/1052))
- `mulmod` uint256 precompile ([#642](https://github.com/succinctlabs/sp1/pull/642))
- aggregation fixes ([#649](https://github.com/succinctlabs/sp1/pull/649))
- complete reduce program ([#565](https://github.com/succinctlabs/sp1/pull/565))
- feat(precompile) bls12-381 add and double precompile ([#448](https://github.com/succinctlabs/sp1/pull/448))
- _(precompile)_ add biguint arithmetic precompiles ([#378](https://github.com/succinctlabs/sp1/pull/378))
- weierstrass decompress precompile ([#440](https://github.com/succinctlabs/sp1/pull/440))
- nested sp1 proof verification ([#494](https://github.com/succinctlabs/sp1/pull/494))
- setup recursion prover crate ([#475](https://github.com/succinctlabs/sp1/pull/475))
- public values ([#455](https://github.com/succinctlabs/sp1/pull/455))
- one cycle input ([#451](https://github.com/succinctlabs/sp1/pull/451))
- _(precompile)_ add bn254 precompile ([#384](https://github.com/succinctlabs/sp1/pull/384))
- Connect CPU to ECALL tables ([#364](https://github.com/succinctlabs/sp1/pull/364))
- Many small features and chores ([#347](https://github.com/succinctlabs/sp1/pull/347))
- program build script ([#296](https://github.com/succinctlabs/sp1/pull/296))
- add musl-libc memcpy ([#279](https://github.com/succinctlabs/sp1/pull/279))
- new README img ([#226](https://github.com/succinctlabs/sp1/pull/226))
- readme updates ([#205](https://github.com/succinctlabs/sp1/pull/205))
- more final touches ([#194](https://github.com/succinctlabs/sp1/pull/194))
- curtaup + release system + cargo prove CLI updates ([#178](https://github.com/succinctlabs/sp1/pull/178))
- (perf) updates from Plonky3 and verifier refactor ([#156](https://github.com/succinctlabs/sp1/pull/156))
- developer experience improvements ([#145](https://github.com/succinctlabs/sp1/pull/145))
- toolchain build from source & install ([#113](https://github.com/succinctlabs/sp1/pull/113))
- io::read io::write ([#126](https://github.com/succinctlabs/sp1/pull/126))
- tracing, profiling, benchmarking ([#99](https://github.com/succinctlabs/sp1/pull/99))

### Fixed

- memory limit ([#1123](https://github.com/succinctlabs/sp1/pull/1123))
- BLS381 decompress ([#1121](https://github.com/succinctlabs/sp1/pull/1121))
- uint256 fixes ([#990](https://github.com/succinctlabs/sp1/pull/990))
- no mangle
- replace `jal` with `call` in entrypoint ([#898](https://github.com/succinctlabs/sp1/pull/898))
- sys_bigint duplicate symbol ([#880](https://github.com/succinctlabs/sp1/pull/880))
- `getrandom` version ([#753](https://github.com/succinctlabs/sp1/pull/753))
- _(zkvm)_ libm math intrinsics ([#287](https://github.com/succinctlabs/sp1/pull/287))
- memcpy & memset ([#282](https://github.com/succinctlabs/sp1/pull/282))
- zkvm crate refactor bug ([#276](https://github.com/succinctlabs/sp1/pull/276))

### Other

- use global workspace version ([#1102](https://github.com/succinctlabs/sp1/pull/1102))
- fix release-plz ([#1088](https://github.com/succinctlabs/sp1/pull/1088))
- add release-plz ([#1086](https://github.com/succinctlabs/sp1/pull/1086))
- _(deps)_ bump serde from 1.0.203 to 1.0.204 ([#1063](https://github.com/succinctlabs/sp1/pull/1063))
- clenaup zkvm
- hm
- cleanup zkvm/lib
- _(deps)_ bump lazy_static from 1.4.0 to 1.5.0
- fix sys rand ([#919](https://github.com/succinctlabs/sp1/pull/919))
- runtime gets printed out 3 times
- hm
- sys rand szn
- Make some functions const ([#774](https://github.com/succinctlabs/sp1/pull/774))
- Clean up TOML files ([#796](https://github.com/succinctlabs/sp1/pull/796))
- update all dependencies ([#689](https://github.com/succinctlabs/sp1/pull/689))
- sdk improvements ([#580](https://github.com/succinctlabs/sp1/pull/580))
- prover tweaks ([#610](https://github.com/succinctlabs/sp1/pull/610))
- sha cleanup + constraints ([#425](https://github.com/succinctlabs/sp1/pull/425))
- split zkvm crate into entrypoint and precompiles ([#275](https://github.com/succinctlabs/sp1/pull/275))
- final touches for public release ([#239](https://github.com/succinctlabs/sp1/pull/239))
- update docs with slight nits ([#224](https://github.com/succinctlabs/sp1/pull/224))
- sp1 rename ([#212](https://github.com/succinctlabs/sp1/pull/212))
- enshrine AlignedBorrow macro ([#209](https://github.com/succinctlabs/sp1/pull/209))
- readme cleanup ([#196](https://github.com/succinctlabs/sp1/pull/196))
- rename succinct to curta ([#192](https://github.com/succinctlabs/sp1/pull/192))
- better curta graphic ([#184](https://github.com/succinctlabs/sp1/pull/184))
- Initial commit
