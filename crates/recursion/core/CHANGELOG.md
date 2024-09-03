# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0](https://github.com/succinctlabs/sp1/compare/sp1-recursion-core-v1.0.1...sp1-recursion-core-v1.1.0) - 2024-08-02

### Added
- update tg ([#1214](https://github.com/succinctlabs/sp1/pull/1214))

### Fixed
- UB from `OpcodeSpecificCols` union ([#1050](https://github.com/succinctlabs/sp1/pull/1050))

### Other
- Merge branch 'main' into dev
- *(deps)* bump arrayref from 0.3.7 to 0.3.8 ([#1154](https://github.com/succinctlabs/sp1/pull/1154))
- add audit reports ([#1142](https://github.com/succinctlabs/sp1/pull/1142))

## [1.0.0-rc1](https://github.com/succinctlabs/sp1/compare/sp1-recursion-core-v1.0.0-rc1...sp1-recursion-core-v1.0.0-rc1) - 2024-07-19

### Added

- parallel recursion tracegen ([#1095](https://github.com/succinctlabs/sp1/pull/1095))
- result instead of exit(1) on trap in recursion ([#1089](https://github.com/succinctlabs/sp1/pull/1089))
- publish sp1 to crates.io ([#1052](https://github.com/succinctlabs/sp1/pull/1052))
- critical constraint changes ([#1046](https://github.com/succinctlabs/sp1/pull/1046))
- plonk circuit optimizations ([#972](https://github.com/succinctlabs/sp1/pull/972))
- poseidon2 hash ([#885](https://github.com/succinctlabs/sp1/pull/885))
- optimize cpu tracegen ([#949](https://github.com/succinctlabs/sp1/pull/949))
- shrink/wrap multi opt
- generic const expr ([#854](https://github.com/succinctlabs/sp1/pull/854))
- plonk prover ([#795](https://github.com/succinctlabs/sp1/pull/795))
- exit code ([#750](https://github.com/succinctlabs/sp1/pull/750))
- _(recursion)_ public values constraints ([#748](https://github.com/succinctlabs/sp1/pull/748))
- _(recursion)_ HALT instruction ([#703](https://github.com/succinctlabs/sp1/pull/703))
- program refactor ([#651](https://github.com/succinctlabs/sp1/pull/651))
- e2e groth16 with contract verifier ([#671](https://github.com/succinctlabs/sp1/pull/671))
- nextgen ci for sp1-prover ([#663](https://github.com/succinctlabs/sp1/pull/663))
- _(recursion)_ Add interactions to poseidon2 skinny ([#658](https://github.com/succinctlabs/sp1/pull/658))
- Adding docs for new `ProverClient` and `groth16` and `compressed` mode ([#627](https://github.com/succinctlabs/sp1/pull/627))
- aggregation fixes ([#649](https://github.com/succinctlabs/sp1/pull/649))
- improve circuit by 3-4x ([#648](https://github.com/succinctlabs/sp1/pull/648))
- _(recursion)_ poseidon2 max constraint degree const generic ([#634](https://github.com/succinctlabs/sp1/pull/634))
- regularize proof shape ([#641](https://github.com/succinctlabs/sp1/pull/641))
- prover tweaks pt4 ([#632](https://github.com/succinctlabs/sp1/pull/632))
- _(recursion)_ jump instruction constraints ([#617](https://github.com/succinctlabs/sp1/pull/617))
- _(recursion)_ cpu branch constraints ([#578](https://github.com/succinctlabs/sp1/pull/578))
- prover tweaks pt 2 ([#607](https://github.com/succinctlabs/sp1/pull/607))
- prover tweaks ([#603](https://github.com/succinctlabs/sp1/pull/603))
- _(recursion)_ memory access timestamp constraints ([#589](https://github.com/succinctlabs/sp1/pull/589))
- enable arbitrary constraint degree ([#593](https://github.com/succinctlabs/sp1/pull/593))
- recursion compress layer + RecursionAirWideDeg3 + RecursionAirSkinnyDeg7 + optimized groth16 ([#590](https://github.com/succinctlabs/sp1/pull/590))
- fixing memory interactions ([#587](https://github.com/succinctlabs/sp1/pull/587))
- _(recursion)_ memory builder + fri-fold precompile ([#581](https://github.com/succinctlabs/sp1/pull/581))
- complete reduce program ([#565](https://github.com/succinctlabs/sp1/pull/565))
- public inputs in gnark circuit ([#576](https://github.com/succinctlabs/sp1/pull/576))
- _(recursion)_ cpu alu constraints ([#570](https://github.com/succinctlabs/sp1/pull/570))
- _(recursion)_ recursion air builder ([#574](https://github.com/succinctlabs/sp1/pull/574))
- simplify compiler load/store ([#572](https://github.com/succinctlabs/sp1/pull/572))
- alu cpu columns ([#562](https://github.com/succinctlabs/sp1/pull/562))
- recursion experiments ([#522](https://github.com/succinctlabs/sp1/pull/522))
- _(recursion)_ impl `Poseidon2WideChip` ([#537](https://github.com/succinctlabs/sp1/pull/537))
- groth16 circuit build script ([#541](https://github.com/succinctlabs/sp1/pull/541))
- verify shard transitions + fixes ([#482](https://github.com/succinctlabs/sp1/pull/482))
- preprocess memory program chip ([#480](https://github.com/succinctlabs/sp1/pull/480))
- nested sp1 proof verification ([#494](https://github.com/succinctlabs/sp1/pull/494))
- verify pc and shard transition in recursive proofs ([#514](https://github.com/succinctlabs/sp1/pull/514))
- recursion profiling ([#521](https://github.com/succinctlabs/sp1/pull/521))
- update to latest p3 ([#515](https://github.com/succinctlabs/sp1/pull/515))
- gnark wrap test + cleanup ([#511](https://github.com/succinctlabs/sp1/pull/511))
- reduce with different configs ([#508](https://github.com/succinctlabs/sp1/pull/508))
- groth16 recursion e2e ([#502](https://github.com/succinctlabs/sp1/pull/502))
- recursion optimizations + compiler cleanup ([#499](https://github.com/succinctlabs/sp1/pull/499))
- recursion vm public values ([#495](https://github.com/succinctlabs/sp1/pull/495))
- shard transition public values ([#466](https://github.com/succinctlabs/sp1/pull/466))
- add support for witness in programs ([#476](https://github.com/succinctlabs/sp1/pull/476))
- fri-fold precompile ([#479](https://github.com/succinctlabs/sp1/pull/479))
- setup recursion prover crate ([#475](https://github.com/succinctlabs/sp1/pull/475))
- gnark recursive verifier ([#457](https://github.com/succinctlabs/sp1/pull/457))
- recursion cpu constraints ([#464](https://github.com/succinctlabs/sp1/pull/464))
- public values ([#455](https://github.com/succinctlabs/sp1/pull/455))
- Preprocessing + recursion ([#450](https://github.com/succinctlabs/sp1/pull/450))
- _(precompile)_ add bn254 precompile ([#384](https://github.com/succinctlabs/sp1/pull/384))
- verify shard ([#444](https://github.com/succinctlabs/sp1/pull/444))
- _(WIP)_ end-to-end verfier ([#439](https://github.com/succinctlabs/sp1/pull/439))
- working two adic pcs verifier in recursive zkvm ([#434](https://github.com/succinctlabs/sp1/pull/434))
- num2bits ([#426](https://github.com/succinctlabs/sp1/pull/426))
- poseidon2 permute ([#423](https://github.com/succinctlabs/sp1/pull/423))
- verify constraints ([#409](https://github.com/succinctlabs/sp1/pull/409))
- poseidon2 air ([#397](https://github.com/succinctlabs/sp1/pull/397))
- checkpoint runtime for constant memory usage ([#389](https://github.com/succinctlabs/sp1/pull/389))
- update to the latest plonky3 version ([#398](https://github.com/succinctlabs/sp1/pull/398))
- array and symbolic evaluation ([#390](https://github.com/succinctlabs/sp1/pull/390))
- extension in vm backend ([#382](https://github.com/succinctlabs/sp1/pull/382))
- new ir ([#373](https://github.com/succinctlabs/sp1/pull/373))
- core recursion air constraints ([#359](https://github.com/succinctlabs/sp1/pull/359))
- recursive DSL initial commit ([#357](https://github.com/succinctlabs/sp1/pull/357))
- recursion program table + memory tracing ([#356](https://github.com/succinctlabs/sp1/pull/356))
- initial recursion core ([#354](https://github.com/succinctlabs/sp1/pull/354))
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
- Allen's exp_reverse_bits_len fixes ([#1074](https://github.com/succinctlabs/sp1/pull/1074))
- multi-builder first/last row issue ([#997](https://github.com/succinctlabs/sp1/pull/997))
- recursion runtime
- changed fixed size for multi table ([#966](https://github.com/succinctlabs/sp1/pull/966))
- frifold flag column consistency ([#946](https://github.com/succinctlabs/sp1/pull/946))
- recursion audit fixes for Issues 7-10 ([#937](https://github.com/succinctlabs/sp1/pull/937))
- memory finalize duplicate address attack from audit ([#934](https://github.com/succinctlabs/sp1/pull/934))
- fix things
- fix
- _(recursion)_ num2bits fixes ([#732](https://github.com/succinctlabs/sp1/pull/732))
- _(recursion)_ poseidon2 external flag ([#747](https://github.com/succinctlabs/sp1/pull/747))
- _(recursion)_ enable mul constraint ([#686](https://github.com/succinctlabs/sp1/pull/686))
- fixes to the multi table ([#669](https://github.com/succinctlabs/sp1/pull/669))
- fri fold mem access ([#660](https://github.com/succinctlabs/sp1/pull/660))
- verify reduced proofs ([#655](https://github.com/succinctlabs/sp1/pull/655))
- _(recursion)_ fixes for fri fold and poseidon2 ([#654](https://github.com/succinctlabs/sp1/pull/654))
- high degree constraints in recursion ([#619](https://github.com/succinctlabs/sp1/pull/619))
- circuit sponge absorb rate ([#618](https://github.com/succinctlabs/sp1/pull/618))
- deferred proofs + cleanup hash_vkey ([#615](https://github.com/succinctlabs/sp1/pull/615))
- comment out MUL constraints ([#602](https://github.com/succinctlabs/sp1/pull/602))
- update Poseidon2 air to match plonky3 ([#600](https://github.com/succinctlabs/sp1/pull/600))
- circuit verification ([#599](https://github.com/succinctlabs/sp1/pull/599))
- poseidon2wide `is_real` ([#591](https://github.com/succinctlabs/sp1/pull/591))
- _(recursion)_ poseidon2 chip matches plonky3 ([#548](https://github.com/succinctlabs/sp1/pull/548))
- observe only non-padded public values ([#523](https://github.com/succinctlabs/sp1/pull/523))
- few regression fixes ([#441](https://github.com/succinctlabs/sp1/pull/441))
- ci ([#401](https://github.com/succinctlabs/sp1/pull/401))

### Other

- poseidon2 parallel tracegen ([#1118](https://github.com/succinctlabs/sp1/pull/1118))
- _(deps)_ bump serde_with from 3.8.3 to 3.9.0 ([#1103](https://github.com/succinctlabs/sp1/pull/1103))
- use global workspace version ([#1102](https://github.com/succinctlabs/sp1/pull/1102))
- fix release-plz ([#1088](https://github.com/succinctlabs/sp1/pull/1088))
- add release-plz ([#1086](https://github.com/succinctlabs/sp1/pull/1086))
- _(deps)_ bump serde_with from 3.8.1 to 3.8.3 ([#1064](https://github.com/succinctlabs/sp1/pull/1064))
- merge main -> dev ([#969](https://github.com/succinctlabs/sp1/pull/969))
- format PR [#934](https://github.com/succinctlabs/sp1/pull/934) ([#939](https://github.com/succinctlabs/sp1/pull/939))
- Refactored is_last and is_first columns; added constraint to make sure that the last real row has is_last on.
- all hail clippy
- Removed defunct test
- please clippy
- Merge branch 'dev' into erabinov/exp_rev_precompile
- Version of exp_rev_precompile
- hm
- remove test
- fixes ([#821](https://github.com/succinctlabs/sp1/pull/821))
- change challenger rate from 16 to 8 ([#807](https://github.com/succinctlabs/sp1/pull/807))
- clippy fixes
- remove unecessary todos in recursion
- Make some functions const ([#774](https://github.com/succinctlabs/sp1/pull/774))
- Clean up TOML files ([#796](https://github.com/succinctlabs/sp1/pull/796))
- _(recursion)_ heap ptr checks ([#775](https://github.com/succinctlabs/sp1/pull/775))
- _(recursion)_ convert ext2felt to hint ([#771](https://github.com/succinctlabs/sp1/pull/771))
- update all dependencies ([#689](https://github.com/succinctlabs/sp1/pull/689))
- _(recursion)_ poseidon2 loose ends ([#672](https://github.com/succinctlabs/sp1/pull/672))
- sdk tweaks ([#653](https://github.com/succinctlabs/sp1/pull/653))
- _(recursion)_ consolidate initial and finalize memory tables ([#656](https://github.com/succinctlabs/sp1/pull/656))
- _(recursion)_ cpu column chores ([#614](https://github.com/succinctlabs/sp1/pull/614))
- _(recursion)_ re-organized cpu chip and trace ([#613](https://github.com/succinctlabs/sp1/pull/613))
- poseidon2 config change ([#609](https://github.com/succinctlabs/sp1/pull/609))
- cleanup prover ([#551](https://github.com/succinctlabs/sp1/pull/551))
- cleanup program + add missing constraints ([#547](https://github.com/succinctlabs/sp1/pull/547))
- make ci faster ([#536](https://github.com/succinctlabs/sp1/pull/536))
- attach dummy wide poseidon2 ([#512](https://github.com/succinctlabs/sp1/pull/512))
- add poseidon2 chip to recursionAIR ([#504](https://github.com/succinctlabs/sp1/pull/504))
- _(recursion)_ reduce program ([#497](https://github.com/succinctlabs/sp1/pull/497))
- for loop optimizations
- update to latest plonky3 main ([#491](https://github.com/succinctlabs/sp1/pull/491))
- sunday cleanup ([#363](https://github.com/succinctlabs/sp1/pull/363))
- recursion core cleanup ([#355](https://github.com/succinctlabs/sp1/pull/355))
- final touches for public release ([#239](https://github.com/succinctlabs/sp1/pull/239))
- update docs with slight nits ([#224](https://github.com/succinctlabs/sp1/pull/224))
- sp1 rename ([#212](https://github.com/succinctlabs/sp1/pull/212))
- enshrine AlignedBorrow macro ([#209](https://github.com/succinctlabs/sp1/pull/209))
- readme cleanup ([#196](https://github.com/succinctlabs/sp1/pull/196))
- rename succinct to curta ([#192](https://github.com/succinctlabs/sp1/pull/192))
- better curta graphic ([#184](https://github.com/succinctlabs/sp1/pull/184))
- Initial commit
