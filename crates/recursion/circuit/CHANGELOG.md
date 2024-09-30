# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0](https://github.com/succinctlabs/sp1/compare/sp1-recursion-circuit-v1.0.1...sp1-recursion-circuit-v1.1.0) - 2024-08-02

### Added
- update tg ([#1214](https://github.com/succinctlabs/sp1/pull/1214))

### Fixed
- BabyBear range check Gnark ([#1225](https://github.com/succinctlabs/sp1/pull/1225))

### Other
- Merge branch 'main' into dev
- prover trait cleanup ([#1170](https://github.com/succinctlabs/sp1/pull/1170))
- add audit reports ([#1142](https://github.com/succinctlabs/sp1/pull/1142))

## [1.0.0-rc1](https://github.com/succinctlabs/sp1/compare/sp1-recursion-circuit-v1.0.0-rc1...sp1-recursion-circuit-v1.0.0-rc1) - 2024-07-19

### Added

- result instead of exit(1) on trap in recursion ([#1089](https://github.com/succinctlabs/sp1/pull/1089))
- publish sp1 to crates.io ([#1052](https://github.com/succinctlabs/sp1/pull/1052))
- critical constraint changes ([#1046](https://github.com/succinctlabs/sp1/pull/1046))
- plonk circuit optimizations ([#972](https://github.com/succinctlabs/sp1/pull/972))
- poseidon2 hash ([#885](https://github.com/succinctlabs/sp1/pull/885))
- use docker by default for gnark ([#890](https://github.com/succinctlabs/sp1/pull/890))
- sp1 core prover opts
- exit code ([#750](https://github.com/succinctlabs/sp1/pull/750))
- program refactor ([#651](https://github.com/succinctlabs/sp1/pull/651))
- e2e groth16 with contract verifier ([#671](https://github.com/succinctlabs/sp1/pull/671))
- improve circuit by 3-4x ([#648](https://github.com/succinctlabs/sp1/pull/648))
- regularize proof shape ([#641](https://github.com/succinctlabs/sp1/pull/641))
- _(sdk)_ auto setup circuit ([#635](https://github.com/succinctlabs/sp1/pull/635))
- arbitrary degree in recursion ([#605](https://github.com/succinctlabs/sp1/pull/605))
- prover tweaks ([#603](https://github.com/succinctlabs/sp1/pull/603))
- enable arbitrary constraint degree ([#593](https://github.com/succinctlabs/sp1/pull/593))
- recursion compress layer + RecursionAirWideDeg3 + RecursionAirSkinnyDeg7 + optimized groth16 ([#590](https://github.com/succinctlabs/sp1/pull/590))
- _(Recursion)_ evaluate constraints in a single expression ([#592](https://github.com/succinctlabs/sp1/pull/592))
- expression caching ([#586](https://github.com/succinctlabs/sp1/pull/586))
- plonk e2e prover ([#582](https://github.com/succinctlabs/sp1/pull/582))
- public inputs in gnark circuit ([#576](https://github.com/succinctlabs/sp1/pull/576))
- e2e groth16 flow ([#549](https://github.com/succinctlabs/sp1/pull/549))
- stark cleanup and verification ([#556](https://github.com/succinctlabs/sp1/pull/556))
- recursion experiments ([#522](https://github.com/succinctlabs/sp1/pull/522))
- groth16 circuit build script ([#541](https://github.com/succinctlabs/sp1/pull/541))
- verify shard transitions + fixes ([#482](https://github.com/succinctlabs/sp1/pull/482))
- recursion profiling ([#521](https://github.com/succinctlabs/sp1/pull/521))
- gnark wrap test + cleanup ([#511](https://github.com/succinctlabs/sp1/pull/511))
- reduce with different configs ([#508](https://github.com/succinctlabs/sp1/pull/508))
- groth16 recursion e2e ([#502](https://github.com/succinctlabs/sp1/pull/502))
- logup batching ([#487](https://github.com/succinctlabs/sp1/pull/487))
- recursion optimizations + compiler cleanup ([#499](https://github.com/succinctlabs/sp1/pull/499))
- recursion vm public values ([#495](https://github.com/succinctlabs/sp1/pull/495))
- cleanup compiler ir ([#496](https://github.com/succinctlabs/sp1/pull/496))
- shard transition public values ([#466](https://github.com/succinctlabs/sp1/pull/466))
- recursion permutation challenges as variables ([#486](https://github.com/succinctlabs/sp1/pull/486))
- add support for witness in programs ([#476](https://github.com/succinctlabs/sp1/pull/476))
- gnark recursive verifier ([#457](https://github.com/succinctlabs/sp1/pull/457))
- Preprocessing + recursion ([#450](https://github.com/succinctlabs/sp1/pull/450))
- working two adic pcs verifier in recursive zkvm ([#434](https://github.com/succinctlabs/sp1/pull/434))
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

- fix overflow when compile to wasm32 ([#812](https://github.com/succinctlabs/sp1/pull/812))
- p3 audit change ([#964](https://github.com/succinctlabs/sp1/pull/964))
- _(recursion)_ assert curve bit length in circuit p2_hash ([#736](https://github.com/succinctlabs/sp1/pull/736))
- fri fold mem access ([#660](https://github.com/succinctlabs/sp1/pull/660))
- verify reduced proofs ([#655](https://github.com/succinctlabs/sp1/pull/655))
- high degree constraints in recursion ([#619](https://github.com/succinctlabs/sp1/pull/619))
- circuit sponge absorb rate ([#618](https://github.com/succinctlabs/sp1/pull/618))
- groth16 prover issues ([#571](https://github.com/succinctlabs/sp1/pull/571))
- observe only non-padded public values ([#523](https://github.com/succinctlabs/sp1/pull/523))
- broken e2e recursion
- don't observe padded public values ([#520](https://github.com/succinctlabs/sp1/pull/520))

### Other

- use global workspace version ([#1102](https://github.com/succinctlabs/sp1/pull/1102))
- fix release-plz ([#1088](https://github.com/succinctlabs/sp1/pull/1088))
- add release-plz ([#1086](https://github.com/succinctlabs/sp1/pull/1086))
- _(deps)_ bump serde from 1.0.203 to 1.0.204 ([#1063](https://github.com/succinctlabs/sp1/pull/1063))
- _(deps)_ bump itertools from 0.12.1 to 0.13.0 ([#817](https://github.com/succinctlabs/sp1/pull/817))
- circuit poseidon2 babybear ([#870](https://github.com/succinctlabs/sp1/pull/870))
- remove unecessary todos in recursion
- permutation argument in circuit ([#804](https://github.com/succinctlabs/sp1/pull/804))
- remove unecessary todo in bb31 to bn254 ([#805](https://github.com/succinctlabs/sp1/pull/805))
- remove unecessary todo
- Clean up TOML files ([#796](https://github.com/succinctlabs/sp1/pull/796))
- update all dependencies ([#689](https://github.com/succinctlabs/sp1/pull/689))
- cleanup prover ([#551](https://github.com/succinctlabs/sp1/pull/551))
- make ci faster ([#536](https://github.com/succinctlabs/sp1/pull/536))
- cleanup for allen ([#518](https://github.com/succinctlabs/sp1/pull/518))
- final touches for public release ([#239](https://github.com/succinctlabs/sp1/pull/239))
- update docs with slight nits ([#224](https://github.com/succinctlabs/sp1/pull/224))
- sp1 rename ([#212](https://github.com/succinctlabs/sp1/pull/212))
- enshrine AlignedBorrow macro ([#209](https://github.com/succinctlabs/sp1/pull/209))
- readme cleanup ([#196](https://github.com/succinctlabs/sp1/pull/196))
- rename succinct to curta ([#192](https://github.com/succinctlabs/sp1/pull/192))
- better curta graphic ([#184](https://github.com/succinctlabs/sp1/pull/184))
- Initial commit
