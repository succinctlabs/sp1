# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.2.1](https://github.com/succinctlabs/sp1/compare/sp1-cli-v1.2.0...sp1-cli-v1.2.1) - 2024-09-04

### Other
- update Cargo.lock dependencies

## [1.2.0-rc2](https://github.com/succinctlabs/sp1/compare/sp1-cli-v1.2.0-rc1...sp1-cli-v1.2.0-rc2) - 2024-08-29

### Other
- update Cargo.lock dependencies

## [1.1.0](https://github.com/succinctlabs/sp1/compare/sp1-cli-v1.0.1...sp1-cli-v1.1.0) - 2024-08-02

### Added
- update tg ([#1214](https://github.com/succinctlabs/sp1/pull/1214))
- use C++ toolchain when building programs that need C ([#1092](https://github.com/succinctlabs/sp1/pull/1092))

### Fixed
- remove nightly in toolchain config ([#1216](https://github.com/succinctlabs/sp1/pull/1216))

### Other
- *(deps)* bump serde_json from 1.0.120 to 1.0.121 ([#1196](https://github.com/succinctlabs/sp1/pull/1196))
- *(deps)* bump anstyle from 1.0.7 to 1.0.8 ([#1194](https://github.com/succinctlabs/sp1/pull/1194))
- Merge branch 'main' into dev

## [1.0.0-rc1](https://github.com/succinctlabs/sp1/compare/sp1-cli-v1.0.0-rc1...sp1-cli-v1.0.0-rc1) - 2024-07-19

### Added

- Add `BuildArgs` to `build_program` ([#995](https://github.com/succinctlabs/sp1/pull/995))
- publish sp1 to crates.io ([#1052](https://github.com/succinctlabs/sp1/pull/1052))
- _(cli)_ use GH token during installation to avoid rate limiting ([#1031](https://github.com/succinctlabs/sp1/pull/1031))
- _(cli)_ build --docker accepts an optional image tag ([#1022](https://github.com/succinctlabs/sp1/pull/1022))
- _(cli)_ allow template version and fix CI ([#1012](https://github.com/succinctlabs/sp1/pull/1012))
- _(cli)_ check for rust usage during installation ([#1006](https://github.com/succinctlabs/sp1/pull/1006))
- _(cli)_ only template contracts when --evm is used ([#1004](https://github.com/succinctlabs/sp1/pull/1004))
- (breaking changes to SDK API) use builder pattern for SDK execute/prove/verify ([#940](https://github.com/succinctlabs/sp1/pull/940))
- cargo prove new from sp1-project-template ([#922](https://github.com/succinctlabs/sp1/pull/922))
- update docs + add some tests around solidity contract export ([#693](https://github.com/succinctlabs/sp1/pull/693))
- e2e groth16 with contract verifier ([#671](https://github.com/succinctlabs/sp1/pull/671))
- aggregation fixes ([#649](https://github.com/succinctlabs/sp1/pull/649))
- _(sdk)_ auto setup circuit ([#635](https://github.com/succinctlabs/sp1/pull/635))
- fix cargo prove new issues ([#542](https://github.com/succinctlabs/sp1/pull/542))
- added `--ignore-rust-version` to `cargo prove build` ([#462](https://github.com/succinctlabs/sp1/pull/462))
- sdk using secp256k1 auth ([#483](https://github.com/succinctlabs/sp1/pull/483))
- sp1-sdk, remote prover ([#370](https://github.com/succinctlabs/sp1/pull/370))
- Many small features and chores ([#347](https://github.com/succinctlabs/sp1/pull/347))
- add instructions for docker usage and setup CI ([#346](https://github.com/succinctlabs/sp1/pull/346))
- _(cli)_ static toolchain + install from releases ([#300](https://github.com/succinctlabs/sp1/pull/300))
- add gitignore in project creation ([#266](https://github.com/succinctlabs/sp1/pull/266))
- _(cli)_ reproducible docker builds ([#254](https://github.com/succinctlabs/sp1/pull/254))
- new README img ([#226](https://github.com/succinctlabs/sp1/pull/226))
- _(cli)_ binary file or hex string input ([#210](https://github.com/succinctlabs/sp1/pull/210))
- readme updates ([#205](https://github.com/succinctlabs/sp1/pull/205))
- release v0.0.1-alpha ([#200](https://github.com/succinctlabs/sp1/pull/200))
- upgrade toolchain to rust 1.75 ([#193](https://github.com/succinctlabs/sp1/pull/193))
- more final touches ([#194](https://github.com/succinctlabs/sp1/pull/194))
- hash function config in prover and verifier ([#186](https://github.com/succinctlabs/sp1/pull/186))
- curtaup + release system + cargo prove CLI updates ([#178](https://github.com/succinctlabs/sp1/pull/178))
- dynamic prover / verifier chips + proof size benchmarking ([#176](https://github.com/succinctlabs/sp1/pull/176))
- (perf) updates from Plonky3 and verifier refactor ([#156](https://github.com/succinctlabs/sp1/pull/156))
- developer experience improvements ([#145](https://github.com/succinctlabs/sp1/pull/145))
- toolchain build from source & install ([#113](https://github.com/succinctlabs/sp1/pull/113))
- io::read io::write ([#126](https://github.com/succinctlabs/sp1/pull/126))
- tracing, profiling, benchmarking ([#99](https://github.com/succinctlabs/sp1/pull/99))
- fix all cargo tests + add ci + rename curta to succinct ([#97](https://github.com/succinctlabs/sp1/pull/97))
- tendermint example + runtime optimizations ([#93](https://github.com/succinctlabs/sp1/pull/93))
- ssz withdrawals example ([#81](https://github.com/succinctlabs/sp1/pull/81))
- simple benchmarks ([#72](https://github.com/succinctlabs/sp1/pull/72))
- cargo prove + examples ([#67](https://github.com/succinctlabs/sp1/pull/67))

### Fixed

- assets branch ([#752](https://github.com/succinctlabs/sp1/pull/752))
- _(ci)_ downgrade `getrandom` ([#751](https://github.com/succinctlabs/sp1/pull/751))
- install toolchain ([#650](https://github.com/succinctlabs/sp1/pull/650))
- moving into toolchain dir ([#646](https://github.com/succinctlabs/sp1/pull/646))
- sp1up ([#643](https://github.com/succinctlabs/sp1/pull/643))
- outdated templates ([#473](https://github.com/succinctlabs/sp1/pull/473))
- _(cli)_ get-target ([#270](https://github.com/succinctlabs/sp1/pull/270))
- edit fibonacci example to use `u128` and note overflow case in quickstart ([#245](https://github.com/succinctlabs/sp1/pull/245))

### Other

- _(deps)_ bump clap from 4.5.8 to 4.5.9 ([#1107](https://github.com/succinctlabs/sp1/pull/1107))
- use global workspace version ([#1102](https://github.com/succinctlabs/sp1/pull/1102))
- fix release-plz ([#1088](https://github.com/succinctlabs/sp1/pull/1088))
- add release-plz ([#1086](https://github.com/succinctlabs/sp1/pull/1086))
- _(deps)_ bump target-lexicon from 0.12.14 to 0.12.15 ([#1067](https://github.com/succinctlabs/sp1/pull/1067))
- get docker url
- hm
- better build
- small fixes
- _(cli)_ informative logging ([#947](https://github.com/succinctlabs/sp1/pull/947))
- Merge branch 'dev' into dependabot/cargo/dev/clap-4.5.8
- _(deps)_ bump serde_json from 1.0.117 to 1.0.120
- get rid of json convert to bin + add proof roundtrip to examples ([#924](https://github.com/succinctlabs/sp1/pull/924))
- x86 mac also works
- failure on sp1 on unsupported target
- _(deps)_ bump clap from 4.5.4 to 4.5.7 ([#908](https://github.com/succinctlabs/sp1/pull/908))
- _(deps)_ bump ubuntu from `3f85b7c` to `e3f92ab` in /cli/docker
- simplify quickstart ([#819](https://github.com/succinctlabs/sp1/pull/819))
- remove unused deps ([#794](https://github.com/succinctlabs/sp1/pull/794))
- Clean up TOML files ([#796](https://github.com/succinctlabs/sp1/pull/796))
- update dev with latest main ([#728](https://github.com/succinctlabs/sp1/pull/728))
- _(deps)_ bump dirs from 4.0.0 to 5.0.1
- update all dependencies ([#689](https://github.com/succinctlabs/sp1/pull/689))
- sdk improvements ([#580](https://github.com/succinctlabs/sp1/pull/580))
- fixing dep tree for `prover`, `recursion`, `core` and `sdk` ([#545](https://github.com/succinctlabs/sp1/pull/545))
- re-organise cpu air constraints ([#538](https://github.com/succinctlabs/sp1/pull/538))
- better error messages on build-toolchain failure ([#490](https://github.com/succinctlabs/sp1/pull/490))
- Typo in 'successfully' corrected across all instances ([#396](https://github.com/succinctlabs/sp1/pull/396))
- remove manual openSSL installation in Dockerfile ([#352](https://github.com/succinctlabs/sp1/pull/352))
- introduce a union type for `opcode_specific_columns` ([#310](https://github.com/succinctlabs/sp1/pull/310))
- refactor air in keccak to not use `offset_of` ([#308](https://github.com/succinctlabs/sp1/pull/308))
- mul trace gen ([#306](https://github.com/succinctlabs/sp1/pull/306))
- clippy ([#255](https://github.com/succinctlabs/sp1/pull/255))
- final touches for public release ([#239](https://github.com/succinctlabs/sp1/pull/239))
- update docs with slight nits ([#224](https://github.com/succinctlabs/sp1/pull/224))
- sp1 rename ([#212](https://github.com/succinctlabs/sp1/pull/212))
- enshrine AlignedBorrow macro ([#209](https://github.com/succinctlabs/sp1/pull/209))
- readme cleanup ([#196](https://github.com/succinctlabs/sp1/pull/196))
- rename succinct to curta ([#192](https://github.com/succinctlabs/sp1/pull/192))
- better curta graphic ([#184](https://github.com/succinctlabs/sp1/pull/184))
- Initial commit
