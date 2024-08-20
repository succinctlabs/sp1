# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0](https://github.com/succinctlabs/sp1/compare/sp1-recursion-gnark-ffi-v1.0.1...sp1-recursion-gnark-ffi-v1.1.0) - 2024-08-02

### Added
- update tg ([#1214](https://github.com/succinctlabs/sp1/pull/1214))

### Fixed
- BabyBear range check Gnark ([#1225](https://github.com/succinctlabs/sp1/pull/1225))

### Other
- *(deps)* bump serde_json from 1.0.120 to 1.0.121 ([#1196](https://github.com/succinctlabs/sp1/pull/1196))

## [1.0.0-rc.1](https://github.com/succinctlabs/sp1/compare/sp1-recursion-gnark-ffi-v1.0.0-rc.1...sp1-recursion-gnark-ffi-v1.0.0-rc.1) - 2024-07-19

### Added

- 1.0.0-rc.1 ([#1126](https://github.com/succinctlabs/sp1/pull/1126))
- publish sp1 to crates.io ([#1052](https://github.com/succinctlabs/sp1/pull/1052))
- update verifier contract templates ([#963](https://github.com/succinctlabs/sp1/pull/963))
- circuit version in proof ([#926](https://github.com/succinctlabs/sp1/pull/926))
- sp1 circuit version ([#899](https://github.com/succinctlabs/sp1/pull/899))
- use docker by default for gnark ([#890](https://github.com/succinctlabs/sp1/pull/890))
- _(sdk)_ add explorer link ([#858](https://github.com/succinctlabs/sp1/pull/858))
- update contract artifacts ([#802](https://github.com/succinctlabs/sp1/pull/802))
- plonk prover ([#795](https://github.com/succinctlabs/sp1/pull/795))
- groth16 feature flag ([#782](https://github.com/succinctlabs/sp1/pull/782))
- add proof verification ([#729](https://github.com/succinctlabs/sp1/pull/729))
- e2e groth16 with contract verifier ([#671](https://github.com/succinctlabs/sp1/pull/671))
- add `groth16` verification to gnark server ([#631](https://github.com/succinctlabs/sp1/pull/631))
- load circuit artifacts in faster ([#638](https://github.com/succinctlabs/sp1/pull/638))
- regularize proof shape ([#641](https://github.com/succinctlabs/sp1/pull/641))
- _(sdk)_ auto setup circuit ([#635](https://github.com/succinctlabs/sp1/pull/635))
- canonicalize build dir paths ([#637](https://github.com/succinctlabs/sp1/pull/637))
- groth16 server ([#594](https://github.com/succinctlabs/sp1/pull/594))
- recursion compress layer + RecursionAirWideDeg3 + RecursionAirSkinnyDeg7 + optimized groth16 ([#590](https://github.com/succinctlabs/sp1/pull/590))
- plonk e2e prover ([#582](https://github.com/succinctlabs/sp1/pull/582))
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

- _(contracts)_ check verifier success ([#983](https://github.com/succinctlabs/sp1/pull/983))
- close unclosed file streams ([#954](https://github.com/succinctlabs/sp1/pull/954))
- some informational fixes from veridise audit ([#953](https://github.com/succinctlabs/sp1/pull/953))
- mock verifier ([#936](https://github.com/succinctlabs/sp1/pull/936))
- reduce minimum Solidity version for SP1 contracts ([#921](https://github.com/succinctlabs/sp1/pull/921))
- plonk feature off by default ([#852](https://github.com/succinctlabs/sp1/pull/852))
- gnark-ffi linking on mac
- solidity verifier
- shutdown groth16 ([#667](https://github.com/succinctlabs/sp1/pull/667))
- better groth16 file handling ([#620](https://github.com/succinctlabs/sp1/pull/620))

### Other

- _(deps)_ bump cc from 1.0.100 to 1.1.5 ([#1104](https://github.com/succinctlabs/sp1/pull/1104))
- use global workspace version ([#1102](https://github.com/succinctlabs/sp1/pull/1102))
- fix release-plz ([#1088](https://github.com/succinctlabs/sp1/pull/1088))
- add release-plz ([#1086](https://github.com/succinctlabs/sp1/pull/1086))
- _(deps)_ bump serde from 1.0.203 to 1.0.204 ([#1063](https://github.com/succinctlabs/sp1/pull/1063))
- _(contracts)_ remove mock verifier and interface autogen ([#1045](https://github.com/succinctlabs/sp1/pull/1045))
- Merge branch 'dev' into dependabot/cargo/dev/log-0.4.22
- _(deps)_ bump serde_json from 1.0.117 to 1.0.120 ([#1001](https://github.com/succinctlabs/sp1/pull/1001))
- _(deps)_ bump num-bigint from 0.4.5 to 0.4.6
- circuit poseidon2 babybear ([#870](https://github.com/succinctlabs/sp1/pull/870))
- docs
- lint
- encode proof solidity
- `prove_plonk` ([#827](https://github.com/succinctlabs/sp1/pull/827))
- Make some functions const ([#774](https://github.com/succinctlabs/sp1/pull/774))
- remove unused deps ([#794](https://github.com/succinctlabs/sp1/pull/794))
- use actual ffi for gnark ([#738](https://github.com/succinctlabs/sp1/pull/738))
- update all dependencies ([#689](https://github.com/succinctlabs/sp1/pull/689))
- gnark folder ([#677](https://github.com/succinctlabs/sp1/pull/677))
- Implement `Prover` on `MockProver` ([#629](https://github.com/succinctlabs/sp1/pull/629))
- prover tweaks ([#610](https://github.com/succinctlabs/sp1/pull/610))
- final touches for public release ([#239](https://github.com/succinctlabs/sp1/pull/239))
- update docs with slight nits ([#224](https://github.com/succinctlabs/sp1/pull/224))
- sp1 rename ([#212](https://github.com/succinctlabs/sp1/pull/212))
- enshrine AlignedBorrow macro ([#209](https://github.com/succinctlabs/sp1/pull/209))
- readme cleanup ([#196](https://github.com/succinctlabs/sp1/pull/196))
- rename succinct to curta ([#192](https://github.com/succinctlabs/sp1/pull/192))
- better curta graphic ([#184](https://github.com/succinctlabs/sp1/pull/184))
- Initial commit
