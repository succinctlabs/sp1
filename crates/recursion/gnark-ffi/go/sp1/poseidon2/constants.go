// Reference: https://github.com/HorizenLabs/poseidon2/blob/bb476b9ca38198cf5092487283c8b8c5d4317c4e/plain_implementations/src/poseidon2/poseidon2_instance_bn256.rs#L32
package poseidon2

import (
	"github.com/consensys/gnark/frontend"
	"github.com/succinctlabs/sp1-recursion-gnark/sp1/babybear"
)

// Poseidon2 round constants for a state consisting of three BN254 field elements.
var rc3 [numExternalRounds + numInternalRounds][width]frontend.Variable

// Poseidon2 round constaints for a state consisting of 16 BabyBear field elements.

var rc16 [30][BABYBEAR_WIDTH]babybear.Variable

func init() {
	init_rc3()
	init_rc16()
}

func init_rc3() {
	round := 0

	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x1d066a255517b7fd8bddd3a93f7804ef7f8fcde48bb4c37a59a09a1a97052816"),
		frontend.Variable("0x29daefb55f6f2dc6ac3f089cebcc6120b7c6fef31367b68eb7238547d32c1610"),
		frontend.Variable("0x1f2cb1624a78ee001ecbd88ad959d7012572d76f08ec5c4f9e8b7ad7b0b4e1d1"),
	}
	round += 1

	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x0aad2e79f15735f2bd77c0ed3d14aa27b11f092a53bbc6e1db0672ded84f31e5"),
		frontend.Variable("0x2252624f8617738cd6f661dd4094375f37028a98f1dece66091ccf1595b43f28"),
		frontend.Variable("0x1a24913a928b38485a65a84a291da1ff91c20626524b2b87d49f4f2c9018d735"),
	}
	round += 1

	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x22fc468f1759b74d7bfc427b5f11ebb10a41515ddff497b14fd6dae1508fc47a"),
		frontend.Variable("0x1059ca787f1f89ed9cd026e9c9ca107ae61956ff0b4121d5efd65515617f6e4d"),
		frontend.Variable("0x02be9473358461d8f61f3536d877de982123011f0bf6f155a45cbbfae8b981ce"),
	}
	round += 1

	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x0ec96c8e32962d462778a749c82ed623aba9b669ac5b8736a1ff3a441a5084a4"),
		frontend.Variable("0x292f906e073677405442d9553c45fa3f5a47a7cdb8c99f9648fb2e4d814df57e"),
		frontend.Variable("0x274982444157b86726c11b9a0f5e39a5cc611160a394ea460c63f0b2ffe5657e"),
	}
	round += 1

	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x1a1d063e54b1e764b63e1855bff015b8cedd192f47308731499573f23597d4b5"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1

	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x26abc66f3fdf8e68839d10956259063708235dccc1aa3793b91b002c5b257c37"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1

	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x0c7c64a9d887385381a578cfed5aed370754427aabca92a70b3c2b12ff4d7be8"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1

	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x1cf5998769e9fab79e17f0b6d08b2d1eba2ebac30dc386b0edd383831354b495"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1

	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x0f5e3a8566be31b7564ca60461e9e08b19828764a9669bc17aba0b97e66b0109"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1

	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x18df6a9d19ea90d895e60e4db0794a01f359a53a180b7d4b42bf3d7a531c976e"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1

	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x04f7bf2c5c0538ac6e4b782c3c6e601ad0ea1d3a3b9d25ef4e324055fa3123dc"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1

	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x29c76ce22255206e3c40058523748531e770c0584aa2328ce55d54628b89ebe6"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1

	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x198d425a45b78e85c053659ab4347f5d65b1b8e9c6108dbe00e0e945dbc5ff15"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1

	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x25ee27ab6296cd5e6af3cc79c598a1daa7ff7f6878b3c49d49d3a9a90c3fdf74"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1

	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x138ea8e0af41a1e024561001c0b6eb1505845d7d0c55b1b2c0f88687a96d1381"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1

	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x306197fb3fab671ef6e7c2cba2eefd0e42851b5b9811f2ca4013370a01d95687"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1

	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x1a0c7d52dc32a4432b66f0b4894d4f1a21db7565e5b4250486419eaf00e8f620"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1

	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x2b46b418de80915f3ff86a8e5c8bdfccebfbe5f55163cd6caa52997da2c54a9f"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1

	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x12d3e0dc0085873701f8b777b9673af9613a1af5db48e05bfb46e312b5829f64"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1

	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x263390cf74dc3a8870f5002ed21d089ffb2bf768230f648dba338a5cb19b3a1f"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1

	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x0a14f33a5fe668a60ac884b4ca607ad0f8abb5af40f96f1d7d543db52b003dcd"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1

	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x28ead9c586513eab1a5e86509d68b2da27be3a4f01171a1dd847df829bc683b9"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1

	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x1c6ab1c328c3c6430972031f1bdb2ac9888f0ea1abe71cffea16cda6e1a7416c"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1

	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x1fc7e71bc0b819792b2500239f7f8de04f6decd608cb98a932346015c5b42c94"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1

	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x03e107eb3a42b2ece380e0d860298f17c0c1e197c952650ee6dd85b93a0ddaa8"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1

	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x2d354a251f381a4669c0d52bf88b772c46452ca57c08697f454505f6941d78cd"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1

	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x094af88ab05d94baf687ef14bc566d1c522551d61606eda3d14b4606826f794b"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1

	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x19705b783bf3d2dc19bcaeabf02f8ca5e1ab5b6f2e3195a9d52b2d249d1396f7"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1

	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x09bf4acc3a8bce3f1fcc33fee54fc5b28723b16b7d740a3e60cef6852271200e"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1

	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x1803f8200db6013c50f83c0c8fab62843413732f301f7058543a073f3f3b5e4e"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1

	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x0f80afb5046244de30595b160b8d1f38bf6fb02d4454c0add41f7fef2faf3e5c"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1

	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x126ee1f8504f15c3d77f0088c1cfc964abcfcf643f4a6fea7dc3f98219529d78"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1

	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x23c203d10cfcc60f69bfb3d919552ca10ffb4ee63175ddf8ef86f991d7d0a591"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1

	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x2a2ae15d8b143709ec0d09705fa3a6303dec1ee4eec2cf747c5a339f7744fb94"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1

	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x07b60dee586ed6ef47e5c381ab6343ecc3d3b3006cb461bbb6b5d89081970b2b"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1

	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x27316b559be3edfd885d95c494c1ae3d8a98a320baa7d152132cfe583c9311bd"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1

	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x1d5c49ba157c32b8d8937cb2d3f84311ef834cc2a743ed662f5f9af0c0342e76"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1

	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x2f8b124e78163b2f332774e0b850b5ec09c01bf6979938f67c24bd5940968488"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1

	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x1e6843a5457416b6dc5b7aa09a9ce21b1d4cba6554e51d84665f75260113b3d5"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1

	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x11cdf00a35f650c55fca25c9929c8ad9a68daf9ac6a189ab1f5bc79f21641d4b"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1

	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x21632de3d3bbc5e42ef36e588158d6d4608b2815c77355b7e82b5b9b7eb560bc"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1

	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x0de625758452efbd97b27025fbd245e0255ae48ef2a329e449d7b5c51c18498a"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1

	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x2ad253c053e75213e2febfd4d976cc01dd9e1e1c6f0fb6b09b09546ba0838098"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1

	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x1d6b169ed63872dc6ec7681ec39b3be93dd49cdd13c813b7d35702e38d60b077"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1

	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x1660b740a143664bb9127c4941b67fed0be3ea70a24d5568c3a54e706cfef7fe"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1

	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x0065a92d1de81f34114f4ca2deef76e0ceacdddb12cf879096a29f10376ccbfe"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1

	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x1f11f065202535987367f823da7d672c353ebe2ccbc4869bcf30d50a5871040d"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1

	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x26596f5c5dd5a5d1b437ce7b14a2c3dd3bd1d1a39b6759ba110852d17df0693e"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1

	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x16f49bc727e45a2f7bf3056efcf8b6d38539c4163a5f1e706743db15af91860f"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1

	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x1abe1deb45b3e3119954175efb331bf4568feaf7ea8b3dc5e1a4e7438dd39e5f"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1

	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x0e426ccab66984d1d8993a74ca548b779f5db92aaec5f102020d34aea15fba59"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1

	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x0e7c30c2e2e8957f4933bd1942053f1f0071684b902d534fa841924303f6a6c6"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1

	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x0812a017ca92cf0a1622708fc7edff1d6166ded6e3528ead4c76e1f31d3fc69d"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1

	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x21a5ade3df2bc1b5bba949d1db96040068afe5026edd7a9c2e276b47cf010d54"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1

	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x01f3035463816c84ad711bf1a058c6c6bd101945f50e5afe72b1a5233f8749ce"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1

	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x0b115572f038c0e2028c2aafc2d06a5e8bf2f9398dbd0fdf4dcaa82b0f0c1c8b"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1

	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x1c38ec0b99b62fd4f0ef255543f50d2e27fc24db42bc910a3460613b6ef59e2f"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1

	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x1c89c6d9666272e8425c3ff1f4ac737b2f5d314606a297d4b1d0b254d880c53e"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1

	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x03326e643580356bf6d44008ae4c042a21ad4880097a5eb38b71e2311bb88f8f"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1

	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x268076b0054fb73f67cee9ea0e51e3ad50f27a6434b5dceb5bdde2299910a4c9"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1

	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x1acd63c67fbc9ab1626ed93491bda32e5da18ea9d8e4f10178d04aa6f8747ad0"),
		frontend.Variable("0x19f8a5d670e8ab66c4e3144be58ef6901bf93375e2323ec3ca8c86cd2a28b5a5"),
		frontend.Variable("0x1c0dc443519ad7a86efa40d2df10a011068193ea51f6c92ae1cfbb5f7b9b6893"),
	}
	round += 1

	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x14b39e7aa4068dbe50fe7190e421dc19fbeab33cb4f6a2c4180e4c3224987d3d"),
		frontend.Variable("0x1d449b71bd826ec58f28c63ea6c561b7b820fc519f01f021afb1e35e28b0795e"),
		frontend.Variable("0x1ea2c9a89baaddbb60fa97fe60fe9d8e89de141689d1252276524dc0a9e987fc"),
	}
	round += 1

	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x0478d66d43535a8cb57e9c1c3d6a2bd7591f9a46a0e9c058134d5cefdb3c7ff1"),
		frontend.Variable("0x19272db71eece6a6f608f3b2717f9cd2662e26ad86c400b21cde5e4a7b00bebe"),
		frontend.Variable("0x14226537335cab33c749c746f09208abb2dd1bd66a87ef75039be846af134166"),
	}
	round += 1

	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x01fd6af15956294f9dfe38c0d976a088b21c21e4a1c2e823f912f44961f9a9ce"),
		frontend.Variable("0x18e5abedd626ec307bca190b8b2cab1aaee2e62ed229ba5a5ad8518d4e5f2a57"),
		frontend.Variable("0x0fc1bbceba0590f5abbdffa6d3b35e3297c021a3a409926d0e2d54dc1c84fda6"),
	}
}

func init_rc16() {
	round := 0

	rc16[round] = [BABYBEAR_WIDTH]babybear.Variable{
		babybear.NewF("2110014213"),
		babybear.NewF("3964964605"),
		babybear.NewF("2190662774"),
		babybear.NewF("2732996483"),
		babybear.NewF("640767983"),
		babybear.NewF("3403899136"),
		babybear.NewF("1716033721"),
		babybear.NewF("1606702601"),
		babybear.NewF("3759873288"),
		babybear.NewF("1466015491"),
		babybear.NewF("1498308946"),
		babybear.NewF("2844375094"),
		babybear.NewF("3042463841"),
		babybear.NewF("1969905919"),
		babybear.NewF("4109944726"),
		babybear.NewF("3925048366"),
	}

	round += 1
	rc16[round] = [BABYBEAR_WIDTH]babybear.Variable{
		babybear.NewF("3706859504"),
		babybear.NewF("759122502"),
		babybear.NewF("3167665446"),
		babybear.NewF("1131812921"),
		babybear.NewF("1080754908"),
		babybear.NewF("4080114493"),
		babybear.NewF("893583089"),
		babybear.NewF("2019677373"),
		babybear.NewF("3128604556"),
		babybear.NewF("580640471"),
		babybear.NewF("3277620260"),
		babybear.NewF("842931656"),
		babybear.NewF("548879852"),
		babybear.NewF("3608554714"),
		babybear.NewF("3575647916"),
		babybear.NewF("81826002"),
	}

	round += 1
	rc16[round] = [BABYBEAR_WIDTH]babybear.Variable{
		babybear.NewF("4289086263"),
		babybear.NewF("1563933798"),
		babybear.NewF("1440025885"),
		babybear.NewF("184445025"),
		babybear.NewF("2598651360"),
		babybear.NewF("1396647410"),
		babybear.NewF("1575877922"),
		babybear.NewF("3303853401"),
		babybear.NewF("137125468"),
		babybear.NewF("765010148"),
		babybear.NewF("633675867"),
		babybear.NewF("2037803363"),
		babybear.NewF("2573389828"),
		babybear.NewF("1895729703"),
		babybear.NewF("541515871"),
		babybear.NewF("1783382863"),
	}

	round += 1
	rc16[round] = [BABYBEAR_WIDTH]babybear.Variable{
		babybear.NewF("2641856484"),
		babybear.NewF("3035743342"),
		babybear.NewF("3672796326"),
		babybear.NewF("245668751"),
		babybear.NewF("2025460432"),
		babybear.NewF("201609705"),
		babybear.NewF("286217151"),
		babybear.NewF("4093475563"),
		babybear.NewF("2519572182"),
		babybear.NewF("3080699870"),
		babybear.NewF("2762001832"),
		babybear.NewF("1244250808"),
		babybear.NewF("606038199"),
		babybear.NewF("3182740831"),
		babybear.NewF("73007766"),
		babybear.NewF("2572204153"),
	}
	round += 1
	rc16[round] = [BABYBEAR_WIDTH]babybear.Variable{
		babybear.NewF("1196780786"),
		babybear.NewF("3447394443"),
		babybear.NewF("747167305"),
		babybear.NewF("2968073607"),
		babybear.NewF("1053214930"),
		babybear.NewF("1074411832"),
		babybear.NewF("4016794508"),
		babybear.NewF("1570312929"),
		babybear.NewF("113576933"),
		babybear.NewF("4042581186"),
		babybear.NewF("3634515733"),
		babybear.NewF("1032701597"),
		babybear.NewF("2364839308"),
		babybear.NewF("3840286918"),
		babybear.NewF("888378655"),
		babybear.NewF("2520191583"),
	}
	round += 1
	rc16[round] = [BABYBEAR_WIDTH]babybear.Variable{
		babybear.NewF("36046858"),
		babybear.NewF("2927525953"),
		babybear.NewF("3912129105"),
		babybear.NewF("4004832531"),
		babybear.NewF("193772436"),
		babybear.NewF("1590247392"),
		babybear.NewF("4125818172"),
		babybear.NewF("2516251696"),
		babybear.NewF("4050945750"),
		babybear.NewF("269498914"),
		babybear.NewF("1973292656"),
		babybear.NewF("891403491"),
		babybear.NewF("1845429189"),
		babybear.NewF("2611996363"),
		babybear.NewF("2310542653"),
		babybear.NewF("4071195740"),
	}
	round += 1
	rc16[round] = [BABYBEAR_WIDTH]babybear.Variable{
		babybear.NewF("3505307391"),
		babybear.NewF("786445290"),
		babybear.NewF("3815313971"),
		babybear.NewF("1111591756"),
		babybear.NewF("4233279834"),
		babybear.NewF("2775453034"),
		babybear.NewF("1991257625"),
		babybear.NewF("2940505809"),
		babybear.NewF("2751316206"),
		babybear.NewF("1028870679"),
		babybear.NewF("1282466273"),
		babybear.NewF("1059053371"),
		babybear.NewF("834521354"),
		babybear.NewF("138721483"),
		babybear.NewF("3100410803"),
		babybear.NewF("3843128331"),
	}
	round += 1
	rc16[round] = [BABYBEAR_WIDTH]babybear.Variable{
		babybear.NewF("3878220780"),
		babybear.NewF("4058162439"),
		babybear.NewF("1478942487"),
		babybear.NewF("799012923"),
		babybear.NewF("496734827"),
		babybear.NewF("3521261236"),
		babybear.NewF("755421082"),
		babybear.NewF("1361409515"),
		babybear.NewF("392099473"),
		babybear.NewF("3178453393"),
		babybear.NewF("4068463721"),
		babybear.NewF("7935614"),
		babybear.NewF("4140885645"),
		babybear.NewF("2150748066"),
		babybear.NewF("1685210312"),
		babybear.NewF("3852983224"),
	}
	round += 1
	rc16[round] = [BABYBEAR_WIDTH]babybear.Variable{
		babybear.NewF("2896943075"),
		babybear.NewF("3087590927"),
		babybear.NewF("992175959"),
		babybear.NewF("970216228"),
		babybear.NewF("3473630090"),
		babybear.NewF("3899670400"),
		babybear.NewF("3603388822"),
		babybear.NewF("2633488197"),
		babybear.NewF("2479406964"),
		babybear.NewF("2420952999"),
		babybear.NewF("1852516800"),
		babybear.NewF("4253075697"),
		babybear.NewF("979699862"),
		babybear.NewF("1163403191"),
		babybear.NewF("1608599874"),
		babybear.NewF("3056104448"),
	}
	round += 1
	rc16[round] = [BABYBEAR_WIDTH]babybear.Variable{
		babybear.NewF("3779109343"),
		babybear.NewF("536205958"),
		babybear.NewF("4183458361"),
		babybear.NewF("1649720295"),
		babybear.NewF("1444912244"),
		babybear.NewF("3122230878"),
		babybear.NewF("384301396"),
		babybear.NewF("4228198516"),
		babybear.NewF("1662916865"),
		babybear.NewF("4082161114"),
		babybear.NewF("2121897314"),
		babybear.NewF("1706239958"),
		babybear.NewF("4166959388"),
		babybear.NewF("1626054781"),
		babybear.NewF("3005858978"),
		babybear.NewF("1431907253"),
	}
	round += 1
	rc16[round] = [BABYBEAR_WIDTH]babybear.Variable{
		babybear.NewF("1418914503"),
		babybear.NewF("1365856753"),
		babybear.NewF("3942715745"),
		babybear.NewF("1429155552"),
		babybear.NewF("3545642795"),
		babybear.NewF("3772474257"),
		babybear.NewF("1621094396"),
		babybear.NewF("2154399145"),
		babybear.NewF("826697382"),
		babybear.NewF("1700781391"),
		babybear.NewF("3539164324"),
		babybear.NewF("652815039"),
		babybear.NewF("442484755"),
		babybear.NewF("2055299391"),
		babybear.NewF("1064289978"),
		babybear.NewF("1152335780"),
	}
	round += 1
	rc16[round] = [BABYBEAR_WIDTH]babybear.Variable{
		babybear.NewF("3417648695"),
		babybear.NewF("186040114"),
		babybear.NewF("3475580573"),
		babybear.NewF("2113941250"),
		babybear.NewF("1779573826"),
		babybear.NewF("1573808590"),
		babybear.NewF("3235694804"),
		babybear.NewF("2922195281"),
		babybear.NewF("1119462702"),
		babybear.NewF("3688305521"),
		babybear.NewF("1849567013"),
		babybear.NewF("667446787"),
		babybear.NewF("753897224"),
		babybear.NewF("1896396780"),
		babybear.NewF("3143026334"),
		babybear.NewF("3829603876"),
	}
	round += 1
	rc16[round] = [BABYBEAR_WIDTH]babybear.Variable{
		babybear.NewF("859661334"),
		babybear.NewF("3898844357"),
		babybear.NewF("180258337"),
		babybear.NewF("2321867017"),
		babybear.NewF("3599002504"),
		babybear.NewF("2886782421"),
		babybear.NewF("3038299378"),
		babybear.NewF("1035366250"),
		babybear.NewF("2038912197"),
		babybear.NewF("2920174523"),
		babybear.NewF("1277696101"),
		babybear.NewF("2785700290"),
		babybear.NewF("3806504335"),
		babybear.NewF("3518858933"),
		babybear.NewF("654843672"),
		babybear.NewF("2127120275"),
	}
	round += 1
	rc16[round] = [BABYBEAR_WIDTH]babybear.Variable{
		babybear.NewF("1548195514"),
		babybear.NewF("2378056027"),
		babybear.NewF("390914568"),
		babybear.NewF("1472049779"),
		babybear.NewF("1552596765"),
		babybear.NewF("1905886441"),
		babybear.NewF("1611959354"),
		babybear.NewF("3653263304"),
		babybear.NewF("3423946386"),
		babybear.NewF("340857935"),
		babybear.NewF("2208879480"),
		babybear.NewF("139364268"),
		babybear.NewF("3447281773"),
		babybear.NewF("3777813707"),
		babybear.NewF("55640413"),
		babybear.NewF("4101901741"),
	}
	round += 1
	rc16[round] = [BABYBEAR_WIDTH]babybear.Variable{
		babybear.NewF("104929687"),
		babybear.NewF("1459980974"),
		babybear.NewF("1831234737"),
		babybear.NewF("457139004"),
		babybear.NewF("2581487628"),
		babybear.NewF("2112044563"),
		babybear.NewF("3567013861"),
		babybear.NewF("2792004347"),
		babybear.NewF("576325418"),
		babybear.NewF("41126132"),
		babybear.NewF("2713562324"),
		babybear.NewF("151213722"),
		babybear.NewF("2891185935"),
		babybear.NewF("546846420"),
		babybear.NewF("2939794919"),
		babybear.NewF("2543469905"),
	}
	round += 1
	rc16[round] = [BABYBEAR_WIDTH]babybear.Variable{
		babybear.NewF("2191909784"),
		babybear.NewF("3315138460"),
		babybear.NewF("530414574"),
		babybear.NewF("1242280418"),
		babybear.NewF("1211740715"),
		babybear.NewF("3993672165"),
		babybear.NewF("2505083323"),
		babybear.NewF("3845798801"),
		babybear.NewF("538768466"),
		babybear.NewF("2063567560"),
		babybear.NewF("3366148274"),
		babybear.NewF("1449831887"),
		babybear.NewF("2408012466"),
		babybear.NewF("294726285"),
		babybear.NewF("3943435493"),
		babybear.NewF("924016661"),
	}
	round += 1
	rc16[round] = [BABYBEAR_WIDTH]babybear.Variable{
		babybear.NewF("3633138367"),
		babybear.NewF("3222789372"),
		babybear.NewF("809116305"),
		babybear.NewF("30100013"),
		babybear.NewF("2655172876"),
		babybear.NewF("2564247117"),
		babybear.NewF("2478649732"),
		babybear.NewF("4113689151"),
		babybear.NewF("4120146082"),
		babybear.NewF("2512308515"),
		babybear.NewF("650406041"),
		babybear.NewF("4240012393"),
		babybear.NewF("2683508708"),
		babybear.NewF("951073977"),
		babybear.NewF("3460081988"),
		babybear.NewF("339124269"),
	}
	round += 1
	rc16[round] = [BABYBEAR_WIDTH]babybear.Variable{
		babybear.NewF("130182653"),
		babybear.NewF("2755946749"),
		babybear.NewF("542600513"),
		babybear.NewF("2816103022"),
		babybear.NewF("1931786340"),
		babybear.NewF("2044470840"),
		babybear.NewF("1709908013"),
		babybear.NewF("2938369043"),
		babybear.NewF("3640399693"),
		babybear.NewF("1374470239"),
		babybear.NewF("2191149676"),
		babybear.NewF("2637495682"),
		babybear.NewF("4236394040"),
		babybear.NewF("2289358846"),
		babybear.NewF("3833368530"),
		babybear.NewF("974546524"),
	}
	round += 1
	rc16[round] = [BABYBEAR_WIDTH]babybear.Variable{
		babybear.NewF("3306659113"),
		babybear.NewF("2234814261"),
		babybear.NewF("1188782305"),
		babybear.NewF("223782844"),
		babybear.NewF("2248980567"),
		babybear.NewF("2309786141"),
		babybear.NewF("2023401627"),
		babybear.NewF("3278877413"),
		babybear.NewF("2022138149"),
		babybear.NewF("575851471"),
		babybear.NewF("1612560780"),
		babybear.NewF("3926656936"),
		babybear.NewF("3318548977"),
		babybear.NewF("2591863678"),
		babybear.NewF("188109355"),
		babybear.NewF("4217723909"),
	}
	round += 1
	rc16[round] = [BABYBEAR_WIDTH]babybear.Variable{
		babybear.NewF("1564209905"),
		babybear.NewF("2154197895"),
		babybear.NewF("2459687029"),
		babybear.NewF("2870634489"),
		babybear.NewF("1375012945"),
		babybear.NewF("1529454825"),
		babybear.NewF("306140690"),
		babybear.NewF("2855578299"),
		babybear.NewF("1246997295"),
		babybear.NewF("3024298763"),
		babybear.NewF("1915270363"),
		babybear.NewF("1218245412"),
		babybear.NewF("2479314020"),
		babybear.NewF("2989827755"),
		babybear.NewF("814378556"),
		babybear.NewF("4039775921"),
	}
	round += 1
	rc16[round] = [BABYBEAR_WIDTH]babybear.Variable{
		babybear.NewF("1165280628"),
		babybear.NewF("1203983801"),
		babybear.NewF("3814740033"),
		babybear.NewF("1919627044"),
		babybear.NewF("600240215"),
		babybear.NewF("773269071"),
		babybear.NewF("486685186"),
		babybear.NewF("4254048810"),
		babybear.NewF("1415023565"),
		babybear.NewF("502840102"),
		babybear.NewF("4225648358"),
		babybear.NewF("510217063"),
		babybear.NewF("166444818"),
		babybear.NewF("1430745893"),
		babybear.NewF("1376516190"),
		babybear.NewF("1775891321"),
	}
	round += 1
	rc16[round] = [BABYBEAR_WIDTH]babybear.Variable{
		babybear.NewF("1170945922"),
		babybear.NewF("1105391877"),
		babybear.NewF("261536467"),
		babybear.NewF("1401687994"),
		babybear.NewF("1022529847"),
		babybear.NewF("2476446456"),
		babybear.NewF("2603844878"),
		babybear.NewF("3706336043"),
		babybear.NewF("3463053714"),
		babybear.NewF("1509644517"),
		babybear.NewF("588552318"),
		babybear.NewF("65252581"),
		babybear.NewF("3696502656"),
		babybear.NewF("2183330763"),
		babybear.NewF("3664021233"),
		babybear.NewF("1643809916"),
	}
	round += 1
	rc16[round] = [BABYBEAR_WIDTH]babybear.Variable{
		babybear.NewF("2922875898"),
		babybear.NewF("3740690643"),
		babybear.NewF("3932461140"),
		babybear.NewF("161156271"),
		babybear.NewF("2619943483"),
		babybear.NewF("4077039509"),
		babybear.NewF("2921201703"),
		babybear.NewF("2085619718"),
		babybear.NewF("2065264646"),
		babybear.NewF("2615693812"),
		babybear.NewF("3116555433"),
		babybear.NewF("246100007"),
		babybear.NewF("4281387154"),
		babybear.NewF("4046141001"),
		babybear.NewF("4027749321"),
		babybear.NewF("111611860"),
	}
	round += 1
	rc16[round] = [BABYBEAR_WIDTH]babybear.Variable{
		babybear.NewF("2066954820"),
		babybear.NewF("2502099969"),
		babybear.NewF("2915053115"),
		babybear.NewF("2362518586"),
		babybear.NewF("366091708"),
		babybear.NewF("2083204932"),
		babybear.NewF("4138385632"),
		babybear.NewF("3195157567"),
		babybear.NewF("1318086382"),
		babybear.NewF("521723799"),
		babybear.NewF("702443405"),
		babybear.NewF("2507670985"),
		babybear.NewF("1760347557"),
		babybear.NewF("2631999893"),
		babybear.NewF("1672737554"),
		babybear.NewF("1060867760"),
	}
	round += 1
	rc16[round] = [BABYBEAR_WIDTH]babybear.Variable{
		babybear.NewF("2359801781"),
		babybear.NewF("2800231467"),
		babybear.NewF("3010357035"),
		babybear.NewF("1035997899"),
		babybear.NewF("1210110952"),
		babybear.NewF("1018506770"),
		babybear.NewF("2799468177"),
		babybear.NewF("1479380761"),
		babybear.NewF("1536021911"),
		babybear.NewF("358993854"),
		babybear.NewF("579904113"),
		babybear.NewF("3432144800"),
		babybear.NewF("3625515809"),
		babybear.NewF("199241497"),
		babybear.NewF("4058304109"),
		babybear.NewF("2590164234"),
	}
	round += 1
	rc16[round] = [BABYBEAR_WIDTH]babybear.Variable{
		babybear.NewF("1688530738"),
		babybear.NewF("1580733335"),
		babybear.NewF("2443981517"),
		babybear.NewF("2206270565"),
		babybear.NewF("2780074229"),
		babybear.NewF("2628739677"),
		babybear.NewF("2940123659"),
		babybear.NewF("4145206827"),
		babybear.NewF("3572278009"),
		babybear.NewF("2779607509"),
		babybear.NewF("1098718697"),
		babybear.NewF("1424913749"),
		babybear.NewF("2224415875"),
		babybear.NewF("1108922178"),
		babybear.NewF("3646272562"),
		babybear.NewF("3935186184"),
	}
	round += 1
	rc16[round] = [BABYBEAR_WIDTH]babybear.Variable{
		babybear.NewF("820046587"),
		babybear.NewF("1393386250"),
		babybear.NewF("2665818575"),
		babybear.NewF("2231782019"),
		babybear.NewF("672377010"),
		babybear.NewF("1920315467"),
		babybear.NewF("1913164407"),
		babybear.NewF("2029526876"),
		babybear.NewF("2629271820"),
		babybear.NewF("384320012"),
		babybear.NewF("4112320585"),
		babybear.NewF("3131824773"),
		babybear.NewF("2347818197"),
		babybear.NewF("2220997386"),
		babybear.NewF("1772368609"),
		babybear.NewF("2579960095"),
	}
	round += 1
	rc16[round] = [BABYBEAR_WIDTH]babybear.Variable{
		babybear.NewF("3544930873"),
		babybear.NewF("225847443"),
		babybear.NewF("3070082278"),
		babybear.NewF("95643305"),
		babybear.NewF("3438572042"),
		babybear.NewF("3312856509"),
		babybear.NewF("615850007"),
		babybear.NewF("1863868773"),
		babybear.NewF("803582265"),
		babybear.NewF("3461976859"),
		babybear.NewF("2903025799"),
		babybear.NewF("1482092434"),
		babybear.NewF("3902972499"),
		babybear.NewF("3872341868"),
		babybear.NewF("1530411808"),
		babybear.NewF("2214923584"),
	}
	round += 1
	rc16[round] = [BABYBEAR_WIDTH]babybear.Variable{
		babybear.NewF("3118792481"),
		babybear.NewF("2241076515"),
		babybear.NewF("3983669831"),
		babybear.NewF("3180915147"),
		babybear.NewF("3838626501"),
		babybear.NewF("1921630011"),
		babybear.NewF("3415351771"),
		babybear.NewF("2249953859"),
		babybear.NewF("3755081630"),
		babybear.NewF("486327260"),
		babybear.NewF("1227575720"),
		babybear.NewF("3643869379"),
		babybear.NewF("2982026073"),
		babybear.NewF("2466043731"),
		babybear.NewF("1982634375"),
		babybear.NewF("3769609014"),
	}
	round += 1
	rc16[round] = [BABYBEAR_WIDTH]babybear.Variable{
		babybear.NewF("2195455495"),
		babybear.NewF("2596863283"),
		babybear.NewF("4244994973"),
		babybear.NewF("1983609348"),
		babybear.NewF("4019674395"),
		babybear.NewF("3469982031"),
		babybear.NewF("1458697570"),
		babybear.NewF("1593516217"),
		babybear.NewF("1963896497"),
		babybear.NewF("3115309118"),
		babybear.NewF("1659132465"),
		babybear.NewF("2536770756"),
		babybear.NewF("3059294171"),
		babybear.NewF("2618031334"),
		babybear.NewF("2040903247"),
		babybear.NewF("3799795076"),
	}
}
