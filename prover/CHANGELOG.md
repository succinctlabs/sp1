# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0-rc.1](https://github.com/succinctlabs/sp1/compare/sp1-prover-v1.0.0-rc.1...sp1-prover-v1.0.0-rc.1) - 2024-07-19

### Added

- 1.0.0-rc.1 ([#1126](https://github.com/succinctlabs/sp1/pull/1126))
- parallel recursion tracegen ([#1095](https://github.com/succinctlabs/sp1/pull/1095))
- result instead of exit(1) on trap in recursion ([#1089](https://github.com/succinctlabs/sp1/pull/1089))
- publish sp1 to crates.io ([#1052](https://github.com/succinctlabs/sp1/pull/1052))
- critical constraint changes ([#1046](https://github.com/succinctlabs/sp1/pull/1046))
- suggest prover network if high cycles ([#1019](https://github.com/succinctlabs/sp1/pull/1019))
- plonk circuit optimizations ([#972](https://github.com/succinctlabs/sp1/pull/972))
- poseidon2 hash ([#885](https://github.com/succinctlabs/sp1/pull/885))
- (breaking changes to SDK API) use builder pattern for SDK execute/prove/verify ([#940](https://github.com/succinctlabs/sp1/pull/940))
- verify subproof in runtime ([#911](https://github.com/succinctlabs/sp1/pull/911))
- _(sdk)_ add explorer link ([#858](https://github.com/succinctlabs/sp1/pull/858))
- generic const expr ([#854](https://github.com/succinctlabs/sp1/pull/854))
- execute() exposes ExecutionReport ([#847](https://github.com/succinctlabs/sp1/pull/847))
- update contract artifacts ([#802](https://github.com/succinctlabs/sp1/pull/802))
- sp1 core prover opts
- batch sized recursion ([#785](https://github.com/succinctlabs/sp1/pull/785))
- plonk prover ([#795](https://github.com/succinctlabs/sp1/pull/795))
- groth16 feature flag ([#782](https://github.com/succinctlabs/sp1/pull/782))
- Implement `verify_groth16` & `prove_groth16` on `MockProver` ([#745](https://github.com/succinctlabs/sp1/pull/745))
- add proof verification ([#729](https://github.com/succinctlabs/sp1/pull/729))
- reduce network prover ([#687](https://github.com/succinctlabs/sp1/pull/687))
- auto rebuild dev artifacts in sdk ([#726](https://github.com/succinctlabs/sp1/pull/726))
- fix execution + proving errors ([#715](https://github.com/succinctlabs/sp1/pull/715))
- update groth16 artifacts ([#711](https://github.com/succinctlabs/sp1/pull/711))
- program refactor ([#651](https://github.com/succinctlabs/sp1/pull/651))
- serial tests in prover crate ([#673](https://github.com/succinctlabs/sp1/pull/673))
- e2e groth16 with contract verifier ([#671](https://github.com/succinctlabs/sp1/pull/671))
- nextgen ci for sp1-prover ([#663](https://github.com/succinctlabs/sp1/pull/663))
- Adding docs for new `ProverClient` and `groth16` and `compressed` mode ([#627](https://github.com/succinctlabs/sp1/pull/627))
- add `groth16` verification to gnark server ([#631](https://github.com/succinctlabs/sp1/pull/631))
- aggregation fixes ([#649](https://github.com/succinctlabs/sp1/pull/649))
- improve circuit by 3-4x ([#648](https://github.com/succinctlabs/sp1/pull/648))
- regularize proof shape ([#641](https://github.com/succinctlabs/sp1/pull/641))
- _(sdk)_ auto setup circuit ([#635](https://github.com/succinctlabs/sp1/pull/635))
- prover tweaks pt4 ([#632](https://github.com/succinctlabs/sp1/pull/632))
- groth16 server ([#594](https://github.com/succinctlabs/sp1/pull/594))
- arbitrary degree in recursion ([#605](https://github.com/succinctlabs/sp1/pull/605))
- prover tweaks ([#603](https://github.com/succinctlabs/sp1/pull/603))
- recursion compress layer + RecursionAirWideDeg3 + RecursionAirSkinnyDeg7 + optimized groth16 ([#590](https://github.com/succinctlabs/sp1/pull/590))
- plonk e2e prover ([#582](https://github.com/succinctlabs/sp1/pull/582))
- complete reduce program ([#565](https://github.com/succinctlabs/sp1/pull/565))
- public inputs in gnark circuit ([#576](https://github.com/succinctlabs/sp1/pull/576))
- e2e groth16 flow ([#549](https://github.com/succinctlabs/sp1/pull/549))
- stark cleanup and verification ([#556](https://github.com/succinctlabs/sp1/pull/556))
- recursion experiments ([#522](https://github.com/succinctlabs/sp1/pull/522))
- groth16 circuit build script ([#541](https://github.com/succinctlabs/sp1/pull/541))
- verify shard transitions + fixes ([#482](https://github.com/succinctlabs/sp1/pull/482))
- nested sp1 proof verification ([#494](https://github.com/succinctlabs/sp1/pull/494))
- verify pc and shard transition in recursive proofs ([#514](https://github.com/succinctlabs/sp1/pull/514))
- recursion profiling ([#521](https://github.com/succinctlabs/sp1/pull/521))
- gnark wrap test + cleanup ([#511](https://github.com/succinctlabs/sp1/pull/511))
- 0 cycle input for recursion program ([#510](https://github.com/succinctlabs/sp1/pull/510))
- reduce with different configs ([#508](https://github.com/succinctlabs/sp1/pull/508))
- _(recursion)_ reduce N sp1/recursive proofs ([#503](https://github.com/succinctlabs/sp1/pull/503))
- recursion optimizations + compiler cleanup ([#499](https://github.com/succinctlabs/sp1/pull/499))
- recursion vm public values ([#495](https://github.com/succinctlabs/sp1/pull/495))
- add support for witness in programs ([#476](https://github.com/succinctlabs/sp1/pull/476))
- setup recursion prover crate ([#475](https://github.com/succinctlabs/sp1/pull/475))
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

- plonk feature off by default ([#852](https://github.com/succinctlabs/sp1/pull/852))
- install for `verify_plonk_bn254` ([#798](https://github.com/succinctlabs/sp1/pull/798))
- groth16 install when in existing runtime ([#735](https://github.com/succinctlabs/sp1/pull/735))
- shutdown groth16 ([#667](https://github.com/succinctlabs/sp1/pull/667))
- _(sdk)_ Small fix for getting vkey digest ([#665](https://github.com/succinctlabs/sp1/pull/665))
- verify reduced proofs ([#655](https://github.com/succinctlabs/sp1/pull/655))
- high degree constraints in recursion ([#619](https://github.com/succinctlabs/sp1/pull/619))
- deferred proofs + cleanup hash_vkey ([#615](https://github.com/succinctlabs/sp1/pull/615))
- groth16 prover issues ([#571](https://github.com/succinctlabs/sp1/pull/571))
- observe only non-padded public values ([#523](https://github.com/succinctlabs/sp1/pull/523))
- broken e2e recursion
- don't observe padded public values ([#520](https://github.com/succinctlabs/sp1/pull/520))

### Other

- prover utilization ([#1100](https://github.com/succinctlabs/sp1/pull/1100))
- _(deps)_ bump clap from 4.5.8 to 4.5.9 ([#1107](https://github.com/succinctlabs/sp1/pull/1107))
- use global workspace version ([#1102](https://github.com/succinctlabs/sp1/pull/1102))
- fix release-plz ([#1088](https://github.com/succinctlabs/sp1/pull/1088))
- add release-plz ([#1086](https://github.com/succinctlabs/sp1/pull/1086))
- remove async crates `sp1-prover` ([#1042](https://github.com/succinctlabs/sp1/pull/1042))
- Merge branch 'dev' into dependabot/cargo/dev/clap-4.5.8
- _(deps)_ bump serde_json from 1.0.117 to 1.0.120 ([#1001](https://github.com/succinctlabs/sp1/pull/1001))
- _(deps)_ bump num-bigint from 0.4.5 to 0.4.6
- merge main -> dev ([#969](https://github.com/succinctlabs/sp1/pull/969))
- cleanup compress ([#928](https://github.com/succinctlabs/sp1/pull/928))
- v1.0.7-testnet ([#930](https://github.com/succinctlabs/sp1/pull/930))
- Fixes from review.
- please clippy
- uncomment
- Merge branch 'dev' into erabinov/exp_rev_precompile
- Version of exp_rev_precompile
- _(deps)_ bump tokio from 1.37.0 to 1.38.0
- update plonk artifacts ([#877](https://github.com/succinctlabs/sp1/pull/877))
- fixes ([#821](https://github.com/succinctlabs/sp1/pull/821))
- bump plonk artifacts ([#864](https://github.com/succinctlabs/sp1/pull/864))
- `prove_plonk` ([#827](https://github.com/succinctlabs/sp1/pull/827))
- hm
- remove unused deps ([#794](https://github.com/succinctlabs/sp1/pull/794))
- Clean up TOML files ([#796](https://github.com/succinctlabs/sp1/pull/796))
- SP1ProvingKey serde ([#772](https://github.com/succinctlabs/sp1/pull/772))
- update groth16 build ([#758](https://github.com/succinctlabs/sp1/pull/758))
- _(prover)_ expose functions for getting core/deferred inputs ([#755](https://github.com/succinctlabs/sp1/pull/755))
- use actual ffi for gnark ([#738](https://github.com/succinctlabs/sp1/pull/738))
- get_cycles don't need emit events ([#697](https://github.com/succinctlabs/sp1/pull/697))
- update all dependencies ([#689](https://github.com/succinctlabs/sp1/pull/689))
- _(recursion)_ poseidon2 loose ends ([#672](https://github.com/succinctlabs/sp1/pull/672))
- gnark folder ([#677](https://github.com/succinctlabs/sp1/pull/677))
- sdk tweaks ([#653](https://github.com/succinctlabs/sp1/pull/653))
- sdk improvements ([#580](https://github.com/succinctlabs/sp1/pull/580))
- prover tweaks ([#610](https://github.com/succinctlabs/sp1/pull/610))
- `get_cycles` ([#595](https://github.com/succinctlabs/sp1/pull/595))
- fixing dep tree for `prover`, `recursion`, `core` and `sdk` ([#545](https://github.com/succinctlabs/sp1/pull/545))
- cleanup prover ([#551](https://github.com/succinctlabs/sp1/pull/551))
- cleanup program + add missing constraints ([#547](https://github.com/succinctlabs/sp1/pull/547))
- make ci faster ([#536](https://github.com/succinctlabs/sp1/pull/536))
- _(recursion)_ reduce program ([#497](https://github.com/succinctlabs/sp1/pull/497))
- final touches for public release ([#239](https://github.com/succinctlabs/sp1/pull/239))
- update docs with slight nits ([#224](https://github.com/succinctlabs/sp1/pull/224))
- sp1 rename ([#212](https://github.com/succinctlabs/sp1/pull/212))
- enshrine AlignedBorrow macro ([#209](https://github.com/succinctlabs/sp1/pull/209))
- readme cleanup ([#196](https://github.com/succinctlabs/sp1/pull/196))
- rename succinct to curta ([#192](https://github.com/succinctlabs/sp1/pull/192))
- better curta graphic ([#184](https://github.com/succinctlabs/sp1/pull/184))
- Initial commit
