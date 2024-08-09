# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0](https://github.com/succinctlabs/sp1/compare/sp1-sdk-v1.0.1...sp1-sdk-v1.1.0) - 2024-08-02

### Added
- update tg ([#1214](https://github.com/succinctlabs/sp1/pull/1214))
- lazy init prover programs and keys ([#1177](https://github.com/succinctlabs/sp1/pull/1177))
- streaming prover for core ([#1146](https://github.com/succinctlabs/sp1/pull/1146))

### Fixed
- verify subproof in execute ([#1204](https://github.com/succinctlabs/sp1/pull/1204))

### Other
- *(deps)* bump serde_json from 1.0.120 to 1.0.121 ([#1196](https://github.com/succinctlabs/sp1/pull/1196))
- *(deps)* bump tokio from 1.38.1 to 1.39.2 ([#1195](https://github.com/succinctlabs/sp1/pull/1195))
- Merge branch 'main' into dev
- *(deps)* bump alloy-sol-types from 0.7.6 to 0.7.7 ([#1152](https://github.com/succinctlabs/sp1/pull/1152))
- *(deps)* bump thiserror from 1.0.61 to 1.0.63 ([#1136](https://github.com/succinctlabs/sp1/pull/1136))
- *(deps)* bump tokio from 1.38.0 to 1.38.1 ([#1137](https://github.com/succinctlabs/sp1/pull/1137))
- add audit reports ([#1142](https://github.com/succinctlabs/sp1/pull/1142))

## [1.0.0-rc.1](https://github.com/succinctlabs/sp1/compare/sp1-sdk-v1.0.0-rc.1...sp1-sdk-v1.0.0-rc.1) - 2024-07-19

### Added

- 1.0.0-rc.1 ([#1126](https://github.com/succinctlabs/sp1/pull/1126))
- publish sp1 to crates.io ([#1052](https://github.com/succinctlabs/sp1/pull/1052))
- critical constraint changes ([#1046](https://github.com/succinctlabs/sp1/pull/1046))
- cycle limit ([#1027](https://github.com/succinctlabs/sp1/pull/1027))
- improve network prover error output ([#991](https://github.com/succinctlabs/sp1/pull/991))
- _(sdk)_ finish mock prover implementation ([#1008](https://github.com/succinctlabs/sp1/pull/1008))
- (breaking changes to SDK API) use builder pattern for SDK execute/prove/verify ([#940](https://github.com/succinctlabs/sp1/pull/940))
- circuit version in proof ([#926](https://github.com/succinctlabs/sp1/pull/926))
- sp1 circuit version ([#899](https://github.com/succinctlabs/sp1/pull/899))
- use docker by default for gnark ([#890](https://github.com/succinctlabs/sp1/pull/890))
- _(sdk)_ add explorer link ([#858](https://github.com/succinctlabs/sp1/pull/858))
- check version for proof requests ([#862](https://github.com/succinctlabs/sp1/pull/862))
- feature flag `alloy_sol_types` ([#850](https://github.com/succinctlabs/sp1/pull/850))
- generic const expr ([#854](https://github.com/succinctlabs/sp1/pull/854))
- execute() exposes ExecutionReport ([#847](https://github.com/succinctlabs/sp1/pull/847))
- encode proof solidity ([#836](https://github.com/succinctlabs/sp1/pull/836))
- switch to ethers ([#826](https://github.com/succinctlabs/sp1/pull/826))
- sp1 core prover opts
- plonk prover ([#795](https://github.com/succinctlabs/sp1/pull/795))
- groth16 feature flag ([#782](https://github.com/succinctlabs/sp1/pull/782))
- Implement `verify_groth16` & `prove_groth16` on `MockProver` ([#745](https://github.com/succinctlabs/sp1/pull/745))
- add proof verification ([#729](https://github.com/succinctlabs/sp1/pull/729))
- reduce network prover ([#687](https://github.com/succinctlabs/sp1/pull/687))
- auto rebuild dev artifacts in sdk ([#726](https://github.com/succinctlabs/sp1/pull/726))
- fix execution + proving errors ([#715](https://github.com/succinctlabs/sp1/pull/715))
- update docs + add some tests around solidity contract export ([#693](https://github.com/succinctlabs/sp1/pull/693))
- add sp1-sdk tests with SP1_DEV=0 for release ci ([#694](https://github.com/succinctlabs/sp1/pull/694))
- program refactor ([#651](https://github.com/succinctlabs/sp1/pull/651))
- e2e groth16 with contract verifier ([#671](https://github.com/succinctlabs/sp1/pull/671))
- nextgen ci for sp1-prover ([#663](https://github.com/succinctlabs/sp1/pull/663))
- Adding docs for new `ProverClient` and `groth16` and `compressed` mode ([#627](https://github.com/succinctlabs/sp1/pull/627))
- add multiple proving modes to network client ([#630](https://github.com/succinctlabs/sp1/pull/630))
- aggregation fixes ([#649](https://github.com/succinctlabs/sp1/pull/649))
- _(recursion)_ poseidon2 max constraint degree const generic ([#634](https://github.com/succinctlabs/sp1/pull/634))
- _(sdk)_ auto setup circuit ([#635](https://github.com/succinctlabs/sp1/pull/635))
- complete reduce program ([#565](https://github.com/succinctlabs/sp1/pull/565))
- update network client with claim and fulfill ([#546](https://github.com/succinctlabs/sp1/pull/546))
- fix cargo prove new issues ([#542](https://github.com/succinctlabs/sp1/pull/542))
- verify shard transitions + fixes ([#482](https://github.com/succinctlabs/sp1/pull/482))
- execute before `prove_remote_async` ([#530](https://github.com/succinctlabs/sp1/pull/530))
- nonce in signed messages ([#507](https://github.com/succinctlabs/sp1/pull/507))
- _(sdk)_ add `prove_async` ([#505](https://github.com/succinctlabs/sp1/pull/505))
- sdk using secp256k1 auth ([#483](https://github.com/succinctlabs/sp1/pull/483))
- recursion vm public values ([#495](https://github.com/succinctlabs/sp1/pull/495))
- relay proofs ([#458](https://github.com/succinctlabs/sp1/pull/458))
- setup recursion prover crate ([#475](https://github.com/succinctlabs/sp1/pull/475))
- public values ([#455](https://github.com/succinctlabs/sp1/pull/455))
- one cycle input ([#451](https://github.com/succinctlabs/sp1/pull/451))
- sp1-sdk, remote prover ([#370](https://github.com/succinctlabs/sp1/pull/370))
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

- _(sdk)_ options warning when using network prover ([#1069](https://github.com/succinctlabs/sp1/pull/1069))
- _(sdk)_ lock axum to 0.7.4 ([#1029](https://github.com/succinctlabs/sp1/pull/1029))
- plonk feature off by default ([#852](https://github.com/succinctlabs/sp1/pull/852))
- fix
- install for `verify_plonk_bn254` ([#798](https://github.com/succinctlabs/sp1/pull/798))
- download Groth16 artifacts on `prove_groth16` invocation ([#674](https://github.com/succinctlabs/sp1/pull/674))
- _(sdk)_ Small fix for getting vkey digest ([#665](https://github.com/succinctlabs/sp1/pull/665))
- verify reduced proofs ([#655](https://github.com/succinctlabs/sp1/pull/655))
- compress before wrap ([#624](https://github.com/succinctlabs/sp1/pull/624))
- fix
- return fulfilled proof ([#573](https://github.com/succinctlabs/sp1/pull/573))
- use REMOTE_PROVE to check local or remote ([#524](https://github.com/succinctlabs/sp1/pull/524))
- `prove_remote` serialization ([#509](https://github.com/succinctlabs/sp1/pull/509))
- use bincode for sdk serialization ([#506](https://github.com/succinctlabs/sp1/pull/506))
- fibonacci io ([#478](https://github.com/succinctlabs/sp1/pull/478))

### Other

- export execution report ([#1112](https://github.com/succinctlabs/sp1/pull/1112))
- prover utilization ([#1100](https://github.com/succinctlabs/sp1/pull/1100))
- _(deps)_ bump async-trait from 0.1.80 to 0.1.81 ([#1105](https://github.com/succinctlabs/sp1/pull/1105))
- _(deps)_ bump sysinfo from 0.30.12 to 0.30.13 ([#1106](https://github.com/succinctlabs/sp1/pull/1106))
- use global workspace version ([#1102](https://github.com/succinctlabs/sp1/pull/1102))
- fix release-plz ([#1088](https://github.com/succinctlabs/sp1/pull/1088))
- add release-plz ([#1086](https://github.com/succinctlabs/sp1/pull/1086))
- remove async crates `sp1-prover` ([#1042](https://github.com/succinctlabs/sp1/pull/1042))
- _(deps)_ bump serde from 1.0.203 to 1.0.204 ([#1063](https://github.com/succinctlabs/sp1/pull/1063))
- switch to p3 from crates.io ([#1038](https://github.com/succinctlabs/sp1/pull/1038))
- hm
- add memory error
- cycle limit
- Merge branch 'dev' into dependabot/cargo/dev/log-0.4.22
- _(deps)_ bump serde_json from 1.0.117 to 1.0.120 ([#1001](https://github.com/succinctlabs/sp1/pull/1001))
- _(deps)_ bump num-bigint from 0.4.5 to 0.4.6 ([#1002](https://github.com/succinctlabs/sp1/pull/1002))
- _(deps)_ bump reqwest-middleware from 0.3.1 to 0.3.2
- _(deps)_ bump strum from 0.26.2 to 0.26.3
- v1.0.7-testnet ([#930](https://github.com/succinctlabs/sp1/pull/930))
- add version to sdk ([#923](https://github.com/succinctlabs/sp1/pull/923))
- hm
- network docs + cleanup ([#913](https://github.com/succinctlabs/sp1/pull/913))
- _(deps)_ bump strum_macros from 0.26.3 to 0.26.4 ([#907](https://github.com/succinctlabs/sp1/pull/907))
- _(deps)_ bump alloy-sol-types from 0.7.4 to 0.7.6 ([#909](https://github.com/succinctlabs/sp1/pull/909))
- _(deps)_ bump tokio from 1.37.0 to 1.38.0 ([#882](https://github.com/succinctlabs/sp1/pull/882))
- _(deps)_ bump strum_macros from 0.26.2 to 0.26.3
- add network requester to requested proof ([#845](https://github.com/succinctlabs/sp1/pull/845))
- Merge branch 'main' into dev
- clean
- change to network
- lint
- prover type
- update comments
- prover type
- encode proof solidity
- `prove_plonk` ([#827](https://github.com/succinctlabs/sp1/pull/827))
- Make some functions const ([#774](https://github.com/succinctlabs/sp1/pull/774))
- remove unused deps ([#794](https://github.com/succinctlabs/sp1/pull/794))
- Clean up TOML files ([#796](https://github.com/succinctlabs/sp1/pull/796))
- merge main into dev ([#801](https://github.com/succinctlabs/sp1/pull/801))
- update dev with latest main ([#728](https://github.com/succinctlabs/sp1/pull/728))
- _(deps)_ bump axum from 0.7.4 to 0.7.5
- update all dependencies ([#689](https://github.com/succinctlabs/sp1/pull/689))
- sdk tweaks ([#653](https://github.com/succinctlabs/sp1/pull/653))
- Implement `Prover` on `MockProver` ([#629](https://github.com/succinctlabs/sp1/pull/629))
- sdk improvements ([#580](https://github.com/succinctlabs/sp1/pull/580))
- fixing dep tree for `prover`, `recursion`, `core` and `sdk` ([#545](https://github.com/succinctlabs/sp1/pull/545))
- cleanup prover ([#551](https://github.com/succinctlabs/sp1/pull/551))
- final touches for public release ([#239](https://github.com/succinctlabs/sp1/pull/239))
- update docs with slight nits ([#224](https://github.com/succinctlabs/sp1/pull/224))
- sp1 rename ([#212](https://github.com/succinctlabs/sp1/pull/212))
- enshrine AlignedBorrow macro ([#209](https://github.com/succinctlabs/sp1/pull/209))
- readme cleanup ([#196](https://github.com/succinctlabs/sp1/pull/196))
- rename succinct to curta ([#192](https://github.com/succinctlabs/sp1/pull/192))
- better curta graphic ([#184](https://github.com/succinctlabs/sp1/pull/184))
- Initial commit
