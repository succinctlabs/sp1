# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0](https://github.com/succinctlabs/sp1/compare/sp1-recursion-compiler-v1.0.1...sp1-recursion-compiler-v1.1.0) - 2024-08-02

### Added
- update tg ([#1214](https://github.com/succinctlabs/sp1/pull/1214))

### Fixed
- BabyBear range check Gnark ([#1225](https://github.com/succinctlabs/sp1/pull/1225))

## [1.0.0-rc1](https://github.com/succinctlabs/sp1/compare/sp1-recursion-compiler-v1.0.0-rc1...sp1-recursion-compiler-v1.0.0-rc1) - 2024-07-19

### Added

- result instead of exit(1) on trap in recursion ([#1089](https://github.com/succinctlabs/sp1/pull/1089))
- publish sp1 to crates.io ([#1052](https://github.com/succinctlabs/sp1/pull/1052))
- plonk circuit optimizations ([#972](https://github.com/succinctlabs/sp1/pull/972))
- poseidon2 hash ([#885](https://github.com/succinctlabs/sp1/pull/885))
- plonk prover ([#795](https://github.com/succinctlabs/sp1/pull/795))
- _(recursion)_ public values constraints ([#748](https://github.com/succinctlabs/sp1/pull/748))
- _(recursion)_ HALT instruction ([#703](https://github.com/succinctlabs/sp1/pull/703))
- program refactor ([#651](https://github.com/succinctlabs/sp1/pull/651))
- improve circuit by 3-4x ([#648](https://github.com/succinctlabs/sp1/pull/648))
- regularize proof shape ([#641](https://github.com/succinctlabs/sp1/pull/641))
- groth16 server ([#594](https://github.com/succinctlabs/sp1/pull/594))
- prover tweaks pt 2 ([#607](https://github.com/succinctlabs/sp1/pull/607))
- prover tweaks ([#603](https://github.com/succinctlabs/sp1/pull/603))
- recursion compress layer + RecursionAirWideDeg3 + RecursionAirSkinnyDeg7 + optimized groth16 ([#590](https://github.com/succinctlabs/sp1/pull/590))
- fixing memory interactions ([#587](https://github.com/succinctlabs/sp1/pull/587))
- _(Recursion)_ evaluate constraints in a single expression ([#592](https://github.com/succinctlabs/sp1/pull/592))
- expression caching ([#586](https://github.com/succinctlabs/sp1/pull/586))
- complete reduce program ([#565](https://github.com/succinctlabs/sp1/pull/565))
- public inputs in gnark circuit ([#576](https://github.com/succinctlabs/sp1/pull/576))
- simplify compiler load/store ([#572](https://github.com/succinctlabs/sp1/pull/572))
- e2e groth16 flow ([#549](https://github.com/succinctlabs/sp1/pull/549))
- alu cpu columns ([#562](https://github.com/succinctlabs/sp1/pull/562))
- recursion experiments ([#522](https://github.com/succinctlabs/sp1/pull/522))
- fix cargo prove new issues ([#542](https://github.com/succinctlabs/sp1/pull/542))
- nested sp1 proof verification ([#494](https://github.com/succinctlabs/sp1/pull/494))
- verify pc and shard transition in recursive proofs ([#514](https://github.com/succinctlabs/sp1/pull/514))
- recursion profiling ([#521](https://github.com/succinctlabs/sp1/pull/521))
- 0 cycle input for recursion program ([#510](https://github.com/succinctlabs/sp1/pull/510))
- reduce with different configs ([#508](https://github.com/succinctlabs/sp1/pull/508))
- groth16 recursion e2e ([#502](https://github.com/succinctlabs/sp1/pull/502))
- _(recursion)_ reduce N sp1/recursive proofs ([#503](https://github.com/succinctlabs/sp1/pull/503))
- recursion optimizations + compiler cleanup ([#499](https://github.com/succinctlabs/sp1/pull/499))
- recursion vm public values ([#495](https://github.com/succinctlabs/sp1/pull/495))
- cleanup compiler ir ([#496](https://github.com/succinctlabs/sp1/pull/496))
- add support for witness in programs ([#476](https://github.com/succinctlabs/sp1/pull/476))
- fri-fold precompile ([#479](https://github.com/succinctlabs/sp1/pull/479))
- gnark recursive verifier ([#457](https://github.com/succinctlabs/sp1/pull/457))
- Preprocessing + recursion ([#450](https://github.com/succinctlabs/sp1/pull/450))
- _(precompile)_ add bn254 precompile ([#384](https://github.com/succinctlabs/sp1/pull/384))
- verify shard ([#444](https://github.com/succinctlabs/sp1/pull/444))
- _(WIP)_ end-to-end verifier ([#439](https://github.com/succinctlabs/sp1/pull/439))
- working two adic pcs verifier in recursive zkvm ([#434](https://github.com/succinctlabs/sp1/pull/434))
- num2bits ([#426](https://github.com/succinctlabs/sp1/pull/426))
- plonky3 update ([#428](https://github.com/succinctlabs/sp1/pull/428))
- dsl derive macro + fri pow witness verify ([#422](https://github.com/succinctlabs/sp1/pull/422))
- poseidon2 permute ([#423](https://github.com/succinctlabs/sp1/pull/423))
- verify constraints ([#409](https://github.com/succinctlabs/sp1/pull/409))
- continue work on fri verifier ([#411](https://github.com/succinctlabs/sp1/pull/411))
- expression caching ([#407](https://github.com/succinctlabs/sp1/pull/407))
- in progress fri verifier ([#402](https://github.com/succinctlabs/sp1/pull/402))
- poseidon2 air ([#397](https://github.com/succinctlabs/sp1/pull/397))
- update to the latest plonky3 version ([#398](https://github.com/succinctlabs/sp1/pull/398))
- verify constraints in DSL + basic verifier setup ([#395](https://github.com/succinctlabs/sp1/pull/395))
- arithmetic bug fix and add compiler to ci ([#394](https://github.com/succinctlabs/sp1/pull/394))
- array and symbolic evaluation ([#390](https://github.com/succinctlabs/sp1/pull/390))
- cleanup and array progress ([#387](https://github.com/succinctlabs/sp1/pull/387))
- gnark if statements evaluation ([#386](https://github.com/succinctlabs/sp1/pull/386))
- extension in vm backend ([#382](https://github.com/succinctlabs/sp1/pull/382))
- gnark e2e build ([#381](https://github.com/succinctlabs/sp1/pull/381))
- new ir ([#373](https://github.com/succinctlabs/sp1/pull/373))
- builder control flow ([#360](https://github.com/succinctlabs/sp1/pull/360))
- recursive DSL initial commit ([#357](https://github.com/succinctlabs/sp1/pull/357))
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

- Allen's Poseidon2 fixes ([#1099](https://github.com/succinctlabs/sp1/pull/1099))
- range check for shard number in recursion ([#952](https://github.com/succinctlabs/sp1/pull/952))
- memory finalize duplicate address attack from audit ([#934](https://github.com/succinctlabs/sp1/pull/934))
- _(recursion)_ num2bits fixes ([#732](https://github.com/succinctlabs/sp1/pull/732))
- verify reduced proofs ([#655](https://github.com/succinctlabs/sp1/pull/655))
- better groth16 file handling ([#620](https://github.com/succinctlabs/sp1/pull/620))
- deferred proofs + cleanup hash_vkey ([#615](https://github.com/succinctlabs/sp1/pull/615))
- run make on Groth16Prover::test ([#577](https://github.com/succinctlabs/sp1/pull/577))
- groth16 prover issues ([#571](https://github.com/succinctlabs/sp1/pull/571))
- don't observe padded public values ([#520](https://github.com/succinctlabs/sp1/pull/520))
- two adic pcs issue when verifying tables of different heights ([#442](https://github.com/succinctlabs/sp1/pull/442))
- compiler conditionals + working challenger ([#430](https://github.com/succinctlabs/sp1/pull/430))
- random ci failure ([#415](https://github.com/succinctlabs/sp1/pull/415))
- caching conflicts ([#413](https://github.com/succinctlabs/sp1/pull/413))
- clippy ([#366](https://github.com/succinctlabs/sp1/pull/366))

### Other

- use global workspace version ([#1102](https://github.com/succinctlabs/sp1/pull/1102))
- fix release-plz ([#1088](https://github.com/succinctlabs/sp1/pull/1088))
- add release-plz ([#1086](https://github.com/succinctlabs/sp1/pull/1086))
- _(deps)_ bump serde from 1.0.203 to 1.0.204 ([#1063](https://github.com/succinctlabs/sp1/pull/1063))
- Fixes from review.
- Update recursion/compiler/src/ir/utils.rs
- please clippy
- Merge branch 'dev' into erabinov/exp_rev_precompile
- Version of exp_rev_precompile
- circuit poseidon2 babybear ([#870](https://github.com/succinctlabs/sp1/pull/870))
- fixes ([#821](https://github.com/succinctlabs/sp1/pull/821))
- remove unnecessary todos in recursion
- Make some functions const ([#774](https://github.com/succinctlabs/sp1/pull/774))
- remove unused deps ([#794](https://github.com/succinctlabs/sp1/pull/794))
- Clean up TOML files ([#796](https://github.com/succinctlabs/sp1/pull/796))
- _(recursion)_ document IR ([#737](https://github.com/succinctlabs/sp1/pull/737))
- _(recursion)_ explicitly don't allow witness and public values related apis in sub-builder ([#744](https://github.com/succinctlabs/sp1/pull/744))
- _(recursion)_ heap ptr checks ([#775](https://github.com/succinctlabs/sp1/pull/775))
- _(recursion)_ convert ext2felt to hint ([#771](https://github.com/succinctlabs/sp1/pull/771))
- update all dependencies ([#689](https://github.com/succinctlabs/sp1/pull/689))
- make ci faster ([#536](https://github.com/succinctlabs/sp1/pull/536))
- cleanup for allen ([#518](https://github.com/succinctlabs/sp1/pull/518))
- _(recursion)_ reduce program ([#497](https://github.com/succinctlabs/sp1/pull/497))
- for loop optimizations
- final touches for public release ([#239](https://github.com/succinctlabs/sp1/pull/239))
- update docs with slight nits ([#224](https://github.com/succinctlabs/sp1/pull/224))
- sp1 rename ([#212](https://github.com/succinctlabs/sp1/pull/212))
- enshrine AlignedBorrow macro ([#209](https://github.com/succinctlabs/sp1/pull/209))
- readme cleanup ([#196](https://github.com/succinctlabs/sp1/pull/196))
- rename succinct to curta ([#192](https://github.com/succinctlabs/sp1/pull/192))
- better curta graphic ([#184](https://github.com/succinctlabs/sp1/pull/184))
- Initial commit
