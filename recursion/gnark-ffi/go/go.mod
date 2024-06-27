module github.com/succinctlabs/sp1-recursion-gnark

go 1.22

require (
	github.com/consensys/gnark v0.10.1-0.20240504023521-d9bfacd7cb60
	github.com/consensys/gnark-crypto v0.12.2-0.20240504013751-564b6f724c3b
)

require github.com/ingonyama-zk/icicle/v2 v2.0.0-20240620074550-c92881fb7d1c

require (
	github.com/bits-and-blooms/bitset v1.8.0 // indirect
	github.com/blang/semver/v4 v4.0.0 // indirect
	github.com/consensys/bavard v0.1.13 // indirect
	github.com/consensys/gnark-ignition-verifier v0.0.0-20230527014722-10693546ab33
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/fxamacker/cbor/v2 v2.5.0 // indirect
	github.com/google/pprof v0.0.0-20230817174616-7a8ec2ada47b // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.19 // indirect
	github.com/mmcloughlin/addchain v0.4.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/rs/zerolog v1.30.0 // indirect
	github.com/stretchr/testify v1.8.4 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/crypto v0.17.0 // indirect
	golang.org/x/sync v0.3.0 // indirect
	golang.org/x/sys v0.15.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	rsc.io/tmplfunc v0.0.3 // indirect
)

replace (
	github.com/consensys/gnark v0.10.1-0.20240504023521-d9bfacd7cb60 => github.com/ingonyama-zk/gnark v0.0.0-20240620124714-84312cbcf8f7
	github.com/consensys/gnark-crypto v0.12.2-0.20240504013751-564b6f724c3b => github.com/ingonyama-zk/gnark-crypto v0.0.0-20240620123528-b1c99a95473d
)
