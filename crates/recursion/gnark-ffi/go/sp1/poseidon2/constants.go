// Reference: https://github.com/HorizenLabs/poseidon2/blob/bb476b9ca38198cf5092487283c8b8c5d4317c4e/plain_implementations/src/poseidon2/poseidon2_instance_bn256.rs#L32
package poseidon2

import (
	"github.com/consensys/gnark/frontend"
	"github.com/succinctlabs/sp1-recursion-gnark/sp1/babybear"
)

// Poseidon2 round constants for a state consisting of three BN254 field elements.
var rc3 [numExternalRounds + numInternalRounds][width]frontend.Variable

// Poseidon2 round constraints for a state consisting of 16 BabyBear field elements.

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
		babybear.NewFConst("2110014213"),
		babybear.NewFConst("3964964605"),
		babybear.NewFConst("2190662774"),
		babybear.NewFConst("2732996483"),
		babybear.NewFConst("640767983"),
		babybear.NewFConst("3403899136"),
		babybear.NewFConst("1716033721"),
		babybear.NewFConst("1606702601"),
		babybear.NewFConst("3759873288"),
		babybear.NewFConst("1466015491"),
		babybear.NewFConst("1498308946"),
		babybear.NewFConst("2844375094"),
		babybear.NewFConst("3042463841"),
		babybear.NewFConst("1969905919"),
		babybear.NewFConst("4109944726"),
		babybear.NewFConst("3925048366"),
	}

	round += 1
	rc16[round] = [BABYBEAR_WIDTH]babybear.Variable{
		babybear.NewFConst("3706859504"),
		babybear.NewFConst("759122502"),
		babybear.NewFConst("3167665446"),
		babybear.NewFConst("1131812921"),
		babybear.NewFConst("1080754908"),
		babybear.NewFConst("4080114493"),
		babybear.NewFConst("893583089"),
		babybear.NewFConst("2019677373"),
		babybear.NewFConst("3128604556"),
		babybear.NewFConst("580640471"),
		babybear.NewFConst("3277620260"),
		babybear.NewFConst("842931656"),
		babybear.NewFConst("548879852"),
		babybear.NewFConst("3608554714"),
		babybear.NewFConst("3575647916"),
		babybear.NewFConst("81826002"),
	}

	round += 1
	rc16[round] = [BABYBEAR_WIDTH]babybear.Variable{
		babybear.NewFConst("4289086263"),
		babybear.NewFConst("1563933798"),
		babybear.NewFConst("1440025885"),
		babybear.NewFConst("184445025"),
		babybear.NewFConst("2598651360"),
		babybear.NewFConst("1396647410"),
		babybear.NewFConst("1575877922"),
		babybear.NewFConst("3303853401"),
		babybear.NewFConst("137125468"),
		babybear.NewFConst("765010148"),
		babybear.NewFConst("633675867"),
		babybear.NewFConst("2037803363"),
		babybear.NewFConst("2573389828"),
		babybear.NewFConst("1895729703"),
		babybear.NewFConst("541515871"),
		babybear.NewFConst("1783382863"),
	}

	round += 1
	rc16[round] = [BABYBEAR_WIDTH]babybear.Variable{
		babybear.NewFConst("2641856484"),
		babybear.NewFConst("3035743342"),
		babybear.NewFConst("3672796326"),
		babybear.NewFConst("245668751"),
		babybear.NewFConst("2025460432"),
		babybear.NewFConst("201609705"),
		babybear.NewFConst("286217151"),
		babybear.NewFConst("4093475563"),
		babybear.NewFConst("2519572182"),
		babybear.NewFConst("3080699870"),
		babybear.NewFConst("2762001832"),
		babybear.NewFConst("1244250808"),
		babybear.NewFConst("606038199"),
		babybear.NewFConst("3182740831"),
		babybear.NewFConst("73007766"),
		babybear.NewFConst("2572204153"),
	}
	round += 1
	rc16[round] = [BABYBEAR_WIDTH]babybear.Variable{
		babybear.NewFConst("1196780786"),
		babybear.NewFConst("3447394443"),
		babybear.NewFConst("747167305"),
		babybear.NewFConst("2968073607"),
		babybear.NewFConst("1053214930"),
		babybear.NewFConst("1074411832"),
		babybear.NewFConst("4016794508"),
		babybear.NewFConst("1570312929"),
		babybear.NewFConst("113576933"),
		babybear.NewFConst("4042581186"),
		babybear.NewFConst("3634515733"),
		babybear.NewFConst("1032701597"),
		babybear.NewFConst("2364839308"),
		babybear.NewFConst("3840286918"),
		babybear.NewFConst("888378655"),
		babybear.NewFConst("2520191583"),
	}
	round += 1
	rc16[round] = [BABYBEAR_WIDTH]babybear.Variable{
		babybear.NewFConst("36046858"),
		babybear.NewFConst("2927525953"),
		babybear.NewFConst("3912129105"),
		babybear.NewFConst("4004832531"),
		babybear.NewFConst("193772436"),
		babybear.NewFConst("1590247392"),
		babybear.NewFConst("4125818172"),
		babybear.NewFConst("2516251696"),
		babybear.NewFConst("4050945750"),
		babybear.NewFConst("269498914"),
		babybear.NewFConst("1973292656"),
		babybear.NewFConst("891403491"),
		babybear.NewFConst("1845429189"),
		babybear.NewFConst("2611996363"),
		babybear.NewFConst("2310542653"),
		babybear.NewFConst("4071195740"),
	}
	round += 1
	rc16[round] = [BABYBEAR_WIDTH]babybear.Variable{
		babybear.NewFConst("3505307391"),
		babybear.NewFConst("786445290"),
		babybear.NewFConst("3815313971"),
		babybear.NewFConst("1111591756"),
		babybear.NewFConst("4233279834"),
		babybear.NewFConst("2775453034"),
		babybear.NewFConst("1991257625"),
		babybear.NewFConst("2940505809"),
		babybear.NewFConst("2751316206"),
		babybear.NewFConst("1028870679"),
		babybear.NewFConst("1282466273"),
		babybear.NewFConst("1059053371"),
		babybear.NewFConst("834521354"),
		babybear.NewFConst("138721483"),
		babybear.NewFConst("3100410803"),
		babybear.NewFConst("3843128331"),
	}
	round += 1
	rc16[round] = [BABYBEAR_WIDTH]babybear.Variable{
		babybear.NewFConst("3878220780"),
		babybear.NewFConst("4058162439"),
		babybear.NewFConst("1478942487"),
		babybear.NewFConst("799012923"),
		babybear.NewFConst("496734827"),
		babybear.NewFConst("3521261236"),
		babybear.NewFConst("755421082"),
		babybear.NewFConst("1361409515"),
		babybear.NewFConst("392099473"),
		babybear.NewFConst("3178453393"),
		babybear.NewFConst("4068463721"),
		babybear.NewFConst("7935614"),
		babybear.NewFConst("4140885645"),
		babybear.NewFConst("2150748066"),
		babybear.NewFConst("1685210312"),
		babybear.NewFConst("3852983224"),
	}
	round += 1
	rc16[round] = [BABYBEAR_WIDTH]babybear.Variable{
		babybear.NewFConst("2896943075"),
		babybear.NewFConst("3087590927"),
		babybear.NewFConst("992175959"),
		babybear.NewFConst("970216228"),
		babybear.NewFConst("3473630090"),
		babybear.NewFConst("3899670400"),
		babybear.NewFConst("3603388822"),
		babybear.NewFConst("2633488197"),
		babybear.NewFConst("2479406964"),
		babybear.NewFConst("2420952999"),
		babybear.NewFConst("1852516800"),
		babybear.NewFConst("4253075697"),
		babybear.NewFConst("979699862"),
		babybear.NewFConst("1163403191"),
		babybear.NewFConst("1608599874"),
		babybear.NewFConst("3056104448"),
	}
	round += 1
	rc16[round] = [BABYBEAR_WIDTH]babybear.Variable{
		babybear.NewFConst("3779109343"),
		babybear.NewFConst("536205958"),
		babybear.NewFConst("4183458361"),
		babybear.NewFConst("1649720295"),
		babybear.NewFConst("1444912244"),
		babybear.NewFConst("3122230878"),
		babybear.NewFConst("384301396"),
		babybear.NewFConst("4228198516"),
		babybear.NewFConst("1662916865"),
		babybear.NewFConst("4082161114"),
		babybear.NewFConst("2121897314"),
		babybear.NewFConst("1706239958"),
		babybear.NewFConst("4166959388"),
		babybear.NewFConst("1626054781"),
		babybear.NewFConst("3005858978"),
		babybear.NewFConst("1431907253"),
	}
	round += 1
	rc16[round] = [BABYBEAR_WIDTH]babybear.Variable{
		babybear.NewFConst("1418914503"),
		babybear.NewFConst("1365856753"),
		babybear.NewFConst("3942715745"),
		babybear.NewFConst("1429155552"),
		babybear.NewFConst("3545642795"),
		babybear.NewFConst("3772474257"),
		babybear.NewFConst("1621094396"),
		babybear.NewFConst("2154399145"),
		babybear.NewFConst("826697382"),
		babybear.NewFConst("1700781391"),
		babybear.NewFConst("3539164324"),
		babybear.NewFConst("652815039"),
		babybear.NewFConst("442484755"),
		babybear.NewFConst("2055299391"),
		babybear.NewFConst("1064289978"),
		babybear.NewFConst("1152335780"),
	}
	round += 1
	rc16[round] = [BABYBEAR_WIDTH]babybear.Variable{
		babybear.NewFConst("3417648695"),
		babybear.NewFConst("186040114"),
		babybear.NewFConst("3475580573"),
		babybear.NewFConst("2113941250"),
		babybear.NewFConst("1779573826"),
		babybear.NewFConst("1573808590"),
		babybear.NewFConst("3235694804"),
		babybear.NewFConst("2922195281"),
		babybear.NewFConst("1119462702"),
		babybear.NewFConst("3688305521"),
		babybear.NewFConst("1849567013"),
		babybear.NewFConst("667446787"),
		babybear.NewFConst("753897224"),
		babybear.NewFConst("1896396780"),
		babybear.NewFConst("3143026334"),
		babybear.NewFConst("3829603876"),
	}
	round += 1
	rc16[round] = [BABYBEAR_WIDTH]babybear.Variable{
		babybear.NewFConst("859661334"),
		babybear.NewFConst("3898844357"),
		babybear.NewFConst("180258337"),
		babybear.NewFConst("2321867017"),
		babybear.NewFConst("3599002504"),
		babybear.NewFConst("2886782421"),
		babybear.NewFConst("3038299378"),
		babybear.NewFConst("1035366250"),
		babybear.NewFConst("2038912197"),
		babybear.NewFConst("2920174523"),
		babybear.NewFConst("1277696101"),
		babybear.NewFConst("2785700290"),
		babybear.NewFConst("3806504335"),
		babybear.NewFConst("3518858933"),
		babybear.NewFConst("654843672"),
		babybear.NewFConst("2127120275"),
	}
	round += 1
	rc16[round] = [BABYBEAR_WIDTH]babybear.Variable{
		babybear.NewFConst("1548195514"),
		babybear.NewFConst("2378056027"),
		babybear.NewFConst("390914568"),
		babybear.NewFConst("1472049779"),
		babybear.NewFConst("1552596765"),
		babybear.NewFConst("1905886441"),
		babybear.NewFConst("1611959354"),
		babybear.NewFConst("3653263304"),
		babybear.NewFConst("3423946386"),
		babybear.NewFConst("340857935"),
		babybear.NewFConst("2208879480"),
		babybear.NewFConst("139364268"),
		babybear.NewFConst("3447281773"),
		babybear.NewFConst("3777813707"),
		babybear.NewFConst("55640413"),
		babybear.NewFConst("4101901741"),
	}
	round += 1
	rc16[round] = [BABYBEAR_WIDTH]babybear.Variable{
		babybear.NewFConst("104929687"),
		babybear.NewFConst("1459980974"),
		babybear.NewFConst("1831234737"),
		babybear.NewFConst("457139004"),
		babybear.NewFConst("2581487628"),
		babybear.NewFConst("2112044563"),
		babybear.NewFConst("3567013861"),
		babybear.NewFConst("2792004347"),
		babybear.NewFConst("576325418"),
		babybear.NewFConst("41126132"),
		babybear.NewFConst("2713562324"),
		babybear.NewFConst("151213722"),
		babybear.NewFConst("2891185935"),
		babybear.NewFConst("546846420"),
		babybear.NewFConst("2939794919"),
		babybear.NewFConst("2543469905"),
	}
	round += 1
	rc16[round] = [BABYBEAR_WIDTH]babybear.Variable{
		babybear.NewFConst("2191909784"),
		babybear.NewFConst("3315138460"),
		babybear.NewFConst("530414574"),
		babybear.NewFConst("1242280418"),
		babybear.NewFConst("1211740715"),
		babybear.NewFConst("3993672165"),
		babybear.NewFConst("2505083323"),
		babybear.NewFConst("3845798801"),
		babybear.NewFConst("538768466"),
		babybear.NewFConst("2063567560"),
		babybear.NewFConst("3366148274"),
		babybear.NewFConst("1449831887"),
		babybear.NewFConst("2408012466"),
		babybear.NewFConst("294726285"),
		babybear.NewFConst("3943435493"),
		babybear.NewFConst("924016661"),
	}
	round += 1
	rc16[round] = [BABYBEAR_WIDTH]babybear.Variable{
		babybear.NewFConst("3633138367"),
		babybear.NewFConst("3222789372"),
		babybear.NewFConst("809116305"),
		babybear.NewFConst("30100013"),
		babybear.NewFConst("2655172876"),
		babybear.NewFConst("2564247117"),
		babybear.NewFConst("2478649732"),
		babybear.NewFConst("4113689151"),
		babybear.NewFConst("4120146082"),
		babybear.NewFConst("2512308515"),
		babybear.NewFConst("650406041"),
		babybear.NewFConst("4240012393"),
		babybear.NewFConst("2683508708"),
		babybear.NewFConst("951073977"),
		babybear.NewFConst("3460081988"),
		babybear.NewFConst("339124269"),
	}
	round += 1
	rc16[round] = [BABYBEAR_WIDTH]babybear.Variable{
		babybear.NewFConst("130182653"),
		babybear.NewFConst("2755946749"),
		babybear.NewFConst("542600513"),
		babybear.NewFConst("2816103022"),
		babybear.NewFConst("1931786340"),
		babybear.NewFConst("2044470840"),
		babybear.NewFConst("1709908013"),
		babybear.NewFConst("2938369043"),
		babybear.NewFConst("3640399693"),
		babybear.NewFConst("1374470239"),
		babybear.NewFConst("2191149676"),
		babybear.NewFConst("2637495682"),
		babybear.NewFConst("4236394040"),
		babybear.NewFConst("2289358846"),
		babybear.NewFConst("3833368530"),
		babybear.NewFConst("974546524"),
	}
	round += 1
	rc16[round] = [BABYBEAR_WIDTH]babybear.Variable{
		babybear.NewFConst("3306659113"),
		babybear.NewFConst("2234814261"),
		babybear.NewFConst("1188782305"),
		babybear.NewFConst("223782844"),
		babybear.NewFConst("2248980567"),
		babybear.NewFConst("2309786141"),
		babybear.NewFConst("2023401627"),
		babybear.NewFConst("3278877413"),
		babybear.NewFConst("2022138149"),
		babybear.NewFConst("575851471"),
		babybear.NewFConst("1612560780"),
		babybear.NewFConst("3926656936"),
		babybear.NewFConst("3318548977"),
		babybear.NewFConst("2591863678"),
		babybear.NewFConst("188109355"),
		babybear.NewFConst("4217723909"),
	}
	round += 1
	rc16[round] = [BABYBEAR_WIDTH]babybear.Variable{
		babybear.NewFConst("1564209905"),
		babybear.NewFConst("2154197895"),
		babybear.NewFConst("2459687029"),
		babybear.NewFConst("2870634489"),
		babybear.NewFConst("1375012945"),
		babybear.NewFConst("1529454825"),
		babybear.NewFConst("306140690"),
		babybear.NewFConst("2855578299"),
		babybear.NewFConst("1246997295"),
		babybear.NewFConst("3024298763"),
		babybear.NewFConst("1915270363"),
		babybear.NewFConst("1218245412"),
		babybear.NewFConst("2479314020"),
		babybear.NewFConst("2989827755"),
		babybear.NewFConst("814378556"),
		babybear.NewFConst("4039775921"),
	}
	round += 1
	rc16[round] = [BABYBEAR_WIDTH]babybear.Variable{
		babybear.NewFConst("1165280628"),
		babybear.NewFConst("1203983801"),
		babybear.NewFConst("3814740033"),
		babybear.NewFConst("1919627044"),
		babybear.NewFConst("600240215"),
		babybear.NewFConst("773269071"),
		babybear.NewFConst("486685186"),
		babybear.NewFConst("4254048810"),
		babybear.NewFConst("1415023565"),
		babybear.NewFConst("502840102"),
		babybear.NewFConst("4225648358"),
		babybear.NewFConst("510217063"),
		babybear.NewFConst("166444818"),
		babybear.NewFConst("1430745893"),
		babybear.NewFConst("1376516190"),
		babybear.NewFConst("1775891321"),
	}
	round += 1
	rc16[round] = [BABYBEAR_WIDTH]babybear.Variable{
		babybear.NewFConst("1170945922"),
		babybear.NewFConst("1105391877"),
		babybear.NewFConst("261536467"),
		babybear.NewFConst("1401687994"),
		babybear.NewFConst("1022529847"),
		babybear.NewFConst("2476446456"),
		babybear.NewFConst("2603844878"),
		babybear.NewFConst("3706336043"),
		babybear.NewFConst("3463053714"),
		babybear.NewFConst("1509644517"),
		babybear.NewFConst("588552318"),
		babybear.NewFConst("65252581"),
		babybear.NewFConst("3696502656"),
		babybear.NewFConst("2183330763"),
		babybear.NewFConst("3664021233"),
		babybear.NewFConst("1643809916"),
	}
	round += 1
	rc16[round] = [BABYBEAR_WIDTH]babybear.Variable{
		babybear.NewFConst("2922875898"),
		babybear.NewFConst("3740690643"),
		babybear.NewFConst("3932461140"),
		babybear.NewFConst("161156271"),
		babybear.NewFConst("2619943483"),
		babybear.NewFConst("4077039509"),
		babybear.NewFConst("2921201703"),
		babybear.NewFConst("2085619718"),
		babybear.NewFConst("2065264646"),
		babybear.NewFConst("2615693812"),
		babybear.NewFConst("3116555433"),
		babybear.NewFConst("246100007"),
		babybear.NewFConst("4281387154"),
		babybear.NewFConst("4046141001"),
		babybear.NewFConst("4027749321"),
		babybear.NewFConst("111611860"),
	}
	round += 1
	rc16[round] = [BABYBEAR_WIDTH]babybear.Variable{
		babybear.NewFConst("2066954820"),
		babybear.NewFConst("2502099969"),
		babybear.NewFConst("2915053115"),
		babybear.NewFConst("2362518586"),
		babybear.NewFConst("366091708"),
		babybear.NewFConst("2083204932"),
		babybear.NewFConst("4138385632"),
		babybear.NewFConst("3195157567"),
		babybear.NewFConst("1318086382"),
		babybear.NewFConst("521723799"),
		babybear.NewFConst("702443405"),
		babybear.NewFConst("2507670985"),
		babybear.NewFConst("1760347557"),
		babybear.NewFConst("2631999893"),
		babybear.NewFConst("1672737554"),
		babybear.NewFConst("1060867760"),
	}
	round += 1
	rc16[round] = [BABYBEAR_WIDTH]babybear.Variable{
		babybear.NewFConst("2359801781"),
		babybear.NewFConst("2800231467"),
		babybear.NewFConst("3010357035"),
		babybear.NewFConst("1035997899"),
		babybear.NewFConst("1210110952"),
		babybear.NewFConst("1018506770"),
		babybear.NewFConst("2799468177"),
		babybear.NewFConst("1479380761"),
		babybear.NewFConst("1536021911"),
		babybear.NewFConst("358993854"),
		babybear.NewFConst("579904113"),
		babybear.NewFConst("3432144800"),
		babybear.NewFConst("3625515809"),
		babybear.NewFConst("199241497"),
		babybear.NewFConst("4058304109"),
		babybear.NewFConst("2590164234"),
	}
	round += 1
	rc16[round] = [BABYBEAR_WIDTH]babybear.Variable{
		babybear.NewFConst("1688530738"),
		babybear.NewFConst("1580733335"),
		babybear.NewFConst("2443981517"),
		babybear.NewFConst("2206270565"),
		babybear.NewFConst("2780074229"),
		babybear.NewFConst("2628739677"),
		babybear.NewFConst("2940123659"),
		babybear.NewFConst("4145206827"),
		babybear.NewFConst("3572278009"),
		babybear.NewFConst("2779607509"),
		babybear.NewFConst("1098718697"),
		babybear.NewFConst("1424913749"),
		babybear.NewFConst("2224415875"),
		babybear.NewFConst("1108922178"),
		babybear.NewFConst("3646272562"),
		babybear.NewFConst("3935186184"),
	}
	round += 1
	rc16[round] = [BABYBEAR_WIDTH]babybear.Variable{
		babybear.NewFConst("820046587"),
		babybear.NewFConst("1393386250"),
		babybear.NewFConst("2665818575"),
		babybear.NewFConst("2231782019"),
		babybear.NewFConst("672377010"),
		babybear.NewFConst("1920315467"),
		babybear.NewFConst("1913164407"),
		babybear.NewFConst("2029526876"),
		babybear.NewFConst("2629271820"),
		babybear.NewFConst("384320012"),
		babybear.NewFConst("4112320585"),
		babybear.NewFConst("3131824773"),
		babybear.NewFConst("2347818197"),
		babybear.NewFConst("2220997386"),
		babybear.NewFConst("1772368609"),
		babybear.NewFConst("2579960095"),
	}
	round += 1
	rc16[round] = [BABYBEAR_WIDTH]babybear.Variable{
		babybear.NewFConst("3544930873"),
		babybear.NewFConst("225847443"),
		babybear.NewFConst("3070082278"),
		babybear.NewFConst("95643305"),
		babybear.NewFConst("3438572042"),
		babybear.NewFConst("3312856509"),
		babybear.NewFConst("615850007"),
		babybear.NewFConst("1863868773"),
		babybear.NewFConst("803582265"),
		babybear.NewFConst("3461976859"),
		babybear.NewFConst("2903025799"),
		babybear.NewFConst("1482092434"),
		babybear.NewFConst("3902972499"),
		babybear.NewFConst("3872341868"),
		babybear.NewFConst("1530411808"),
		babybear.NewFConst("2214923584"),
	}
	round += 1
	rc16[round] = [BABYBEAR_WIDTH]babybear.Variable{
		babybear.NewFConst("3118792481"),
		babybear.NewFConst("2241076515"),
		babybear.NewFConst("3983669831"),
		babybear.NewFConst("3180915147"),
		babybear.NewFConst("3838626501"),
		babybear.NewFConst("1921630011"),
		babybear.NewFConst("3415351771"),
		babybear.NewFConst("2249953859"),
		babybear.NewFConst("3755081630"),
		babybear.NewFConst("486327260"),
		babybear.NewFConst("1227575720"),
		babybear.NewFConst("3643869379"),
		babybear.NewFConst("2982026073"),
		babybear.NewFConst("2466043731"),
		babybear.NewFConst("1982634375"),
		babybear.NewFConst("3769609014"),
	}
	round += 1
	rc16[round] = [BABYBEAR_WIDTH]babybear.Variable{
		babybear.NewFConst("2195455495"),
		babybear.NewFConst("2596863283"),
		babybear.NewFConst("4244994973"),
		babybear.NewFConst("1983609348"),
		babybear.NewFConst("4019674395"),
		babybear.NewFConst("3469982031"),
		babybear.NewFConst("1458697570"),
		babybear.NewFConst("1593516217"),
		babybear.NewFConst("1963896497"),
		babybear.NewFConst("3115309118"),
		babybear.NewFConst("1659132465"),
		babybear.NewFConst("2536770756"),
		babybear.NewFConst("3059294171"),
		babybear.NewFConst("2618031334"),
		babybear.NewFConst("2040903247"),
		babybear.NewFConst("3799795076"),
	}
}
