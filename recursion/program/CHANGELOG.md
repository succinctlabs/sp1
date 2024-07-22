# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0-rc.1](https://github.com/succinctlabs/sp1/compare/sp1-recursion-program-v1.0.0-rc.1...sp1-recursion-program-v1.0.0-rc.1) - 2024-07-19

### Added

- parallel recursion tracegen ([#1095](https://github.com/succinctlabs/sp1/pull/1095))
- result instead of exit(1) on trap in recursion ([#1089](https://github.com/succinctlabs/sp1/pull/1089))
- publish sp1 to crates.io ([#1052](https://github.com/succinctlabs/sp1/pull/1052))
- critical constraint changes ([#1046](https://github.com/succinctlabs/sp1/pull/1046))
- suggest prover network if high cycles ([#1019](https://github.com/succinctlabs/sp1/pull/1019))
- plonk circuit optimizations ([#972](https://github.com/succinctlabs/sp1/pull/972))
- poseidon2 hash ([#885](https://github.com/succinctlabs/sp1/pull/885))
- generic const expr ([#854](https://github.com/succinctlabs/sp1/pull/854))
- sp1 core prover opts
- exit code ([#750](https://github.com/succinctlabs/sp1/pull/750))
- _(recursion)_ public values constraints ([#748](https://github.com/succinctlabs/sp1/pull/748))
- reduce network prover ([#687](https://github.com/succinctlabs/sp1/pull/687))
- fix execution + proving errors ([#715](https://github.com/succinctlabs/sp1/pull/715))
- _(recursion)_ HALT instruction ([#703](https://github.com/succinctlabs/sp1/pull/703))
- ci refactor ([#684](https://github.com/succinctlabs/sp1/pull/684))
- program refactor ([#651](https://github.com/succinctlabs/sp1/pull/651))
- Adding docs for new `ProverClient` and `groth16` and `compressed` mode ([#627](https://github.com/succinctlabs/sp1/pull/627))
- arbitrary degree in recursion ([#605](https://github.com/succinctlabs/sp1/pull/605))
- prover tweaks pt 2 ([#607](https://github.com/succinctlabs/sp1/pull/607))
- prover tweaks ([#603](https://github.com/succinctlabs/sp1/pull/603))
- _(recursion)_ memory access timestamp constraints ([#589](https://github.com/succinctlabs/sp1/pull/589))
- enable arbitrary constraint degree ([#593](https://github.com/succinctlabs/sp1/pull/593))
- recursion compress layer + RecursionAirWideDeg3 + RecursionAirSkinnyDeg7 + optimized groth16 ([#590](https://github.com/succinctlabs/sp1/pull/590))
- _(Recursion)_ evaluate constraints in a single expression ([#592](https://github.com/succinctlabs/sp1/pull/592))
- expression caching ([#586](https://github.com/succinctlabs/sp1/pull/586))
- complete reduce program ([#565](https://github.com/succinctlabs/sp1/pull/565))
- e2e groth16 flow ([#549](https://github.com/succinctlabs/sp1/pull/549))
- stark cleanup and verification ([#556](https://github.com/succinctlabs/sp1/pull/556))
- recursion experiments ([#522](https://github.com/succinctlabs/sp1/pull/522))
- groth16 circuit build script ([#541](https://github.com/succinctlabs/sp1/pull/541))
- verify shard transitions + fixes ([#482](https://github.com/succinctlabs/sp1/pull/482))
- nested sp1 proof verification ([#494](https://github.com/succinctlabs/sp1/pull/494))
- verify pc and shard transition in recursive proofs ([#514](https://github.com/succinctlabs/sp1/pull/514))
- recursion profiling ([#521](https://github.com/succinctlabs/sp1/pull/521))
- update to latest p3 ([#515](https://github.com/succinctlabs/sp1/pull/515))
- gnark wrap test + cleanup ([#511](https://github.com/succinctlabs/sp1/pull/511))
- 0 cycle input for recursion program ([#510](https://github.com/succinctlabs/sp1/pull/510))
- reduce with different configs ([#508](https://github.com/succinctlabs/sp1/pull/508))
- sdk using secp256k1 auth ([#483](https://github.com/succinctlabs/sp1/pull/483))
- logup batching ([#487](https://github.com/succinctlabs/sp1/pull/487))
- _(recursion)_ reduce N sp1/recursive proofs ([#503](https://github.com/succinctlabs/sp1/pull/503))
- recursion optimizations + compiler cleanup ([#499](https://github.com/succinctlabs/sp1/pull/499))
- recursion vm public values ([#495](https://github.com/succinctlabs/sp1/pull/495))
- cleanup compiler ir ([#496](https://github.com/succinctlabs/sp1/pull/496))
- shard transition public values ([#466](https://github.com/succinctlabs/sp1/pull/466))
- recursion permutation challenges as variables ([#486](https://github.com/succinctlabs/sp1/pull/486))
- add support for witness in programs ([#476](https://github.com/succinctlabs/sp1/pull/476))
- fri-fold precompile ([#479](https://github.com/succinctlabs/sp1/pull/479))
- setup recursion prover crate ([#475](https://github.com/succinctlabs/sp1/pull/475))
- gnark recursive verifier ([#457](https://github.com/succinctlabs/sp1/pull/457))
- add shard to byte and program table ([#463](https://github.com/succinctlabs/sp1/pull/463))
- recursion cpu constraints ([#464](https://github.com/succinctlabs/sp1/pull/464))
- public values ([#455](https://github.com/succinctlabs/sp1/pull/455))
- Preprocessing + recursion ([#450](https://github.com/succinctlabs/sp1/pull/450))
- sp1-sdk, remote prover ([#370](https://github.com/succinctlabs/sp1/pull/370))
- _(precompile)_ add bn254 precompile ([#384](https://github.com/succinctlabs/sp1/pull/384))
- verify shard ([#444](https://github.com/succinctlabs/sp1/pull/444))
- _(WIP)_ end-to-end verfier ([#439](https://github.com/succinctlabs/sp1/pull/439))
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

- incorrect checks on deferred digest ([#1116](https://github.com/succinctlabs/sp1/pull/1116))
- use correct value for blowup ([#965](https://github.com/succinctlabs/sp1/pull/965))
- p3 audit change ([#964](https://github.com/succinctlabs/sp1/pull/964))
- some informational fixes from veridise audit ([#953](https://github.com/succinctlabs/sp1/pull/953))
- set sponge state to be zero ([#951](https://github.com/succinctlabs/sp1/pull/951))
- range check for shard number in recursion ([#952](https://github.com/succinctlabs/sp1/pull/952))
- memory finalize duplicate address attack from audit ([#934](https://github.com/succinctlabs/sp1/pull/934))
- fix things
- unnecessary pc constraint ([#749](https://github.com/succinctlabs/sp1/pull/749))
- _(recursion)_ enable mul constraint ([#686](https://github.com/succinctlabs/sp1/pull/686))
- verify reduced proofs ([#655](https://github.com/succinctlabs/sp1/pull/655))
- high degree constraints in recursion ([#619](https://github.com/succinctlabs/sp1/pull/619))
- deferred proofs + cleanup hash_vkey ([#615](https://github.com/succinctlabs/sp1/pull/615))
- observe only non-padded public values ([#523](https://github.com/succinctlabs/sp1/pull/523))
- broken e2e recursion
- don't observe padded public values ([#520](https://github.com/succinctlabs/sp1/pull/520))
- public inputs in recursion program ([#467](https://github.com/succinctlabs/sp1/pull/467))

### Other

- use global workspace version ([#1102](https://github.com/succinctlabs/sp1/pull/1102))
- fix release-plz ([#1088](https://github.com/succinctlabs/sp1/pull/1088))
- add release-plz ([#1086](https://github.com/succinctlabs/sp1/pull/1086))
- _(deps)_ bump serde from 1.0.203 to 1.0.204 ([#1063](https://github.com/succinctlabs/sp1/pull/1063))
- updated p3 dependency to 0.1.3 ([#1059](https://github.com/succinctlabs/sp1/pull/1059))
- merge main -> dev ([#969](https://github.com/succinctlabs/sp1/pull/969))
- Fixes from review.
- Reverted to exp_rev_bits_len_fast
- please clippy
- Merge branch 'dev' into erabinov/exp_rev_precompile
- Version of exp_rev_precompile
- fixes ([#821](https://github.com/succinctlabs/sp1/pull/821))
- program doc and remove unnecessary clones ([#857](https://github.com/succinctlabs/sp1/pull/857))
- recursive program docs ([#855](https://github.com/succinctlabs/sp1/pull/855))
- fmt
- change challenger rate from 16 to 8 ([#807](https://github.com/succinctlabs/sp1/pull/807))
- remove todos in recursion ([#809](https://github.com/succinctlabs/sp1/pull/809))
- require cpu shard in verifier ([#808](https://github.com/succinctlabs/sp1/pull/808))
- clippy
- hm
- Make some functions const ([#774](https://github.com/succinctlabs/sp1/pull/774))
- remove unused deps ([#794](https://github.com/succinctlabs/sp1/pull/794))
- Clean up TOML files ([#796](https://github.com/succinctlabs/sp1/pull/796))
- update all dependencies ([#689](https://github.com/succinctlabs/sp1/pull/689))
- fixing dep tree for `prover`, `recursion`, `core` and `sdk` ([#545](https://github.com/succinctlabs/sp1/pull/545))
- cleanup prover ([#551](https://github.com/succinctlabs/sp1/pull/551))
- cleanup program + add missing constraints ([#547](https://github.com/succinctlabs/sp1/pull/547))
- make ci faster ([#536](https://github.com/succinctlabs/sp1/pull/536))
- _(recursion)_ reduce program ([#497](https://github.com/succinctlabs/sp1/pull/497))
- for loop optimizations
- update to latest plonky3 main ([#491](https://github.com/succinctlabs/sp1/pull/491))
- final touches for public release ([#239](https://github.com/succinctlabs/sp1/pull/239))
- update docs with slight nits ([#224](https://github.com/succinctlabs/sp1/pull/224))
- sp1 rename ([#212](https://github.com/succinctlabs/sp1/pull/212))
- enshrine AlignedBorrow macro ([#209](https://github.com/succinctlabs/sp1/pull/209))
- readme cleanup ([#196](https://github.com/succinctlabs/sp1/pull/196))
- rename succinct to curta ([#192](https://github.com/succinctlabs/sp1/pull/192))
- better curta graphic ([#184](https://github.com/succinctlabs/sp1/pull/184))
- Initial commit
