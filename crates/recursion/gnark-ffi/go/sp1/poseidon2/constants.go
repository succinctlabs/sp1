package poseidon2

import (
	"github.com/consensys/gnark/frontend"
	"github.com/succinctlabs/sp1-recursion-gnark/sp1/babybear"
)

// Poseidon2 round constants for a state consisting of three BLS12-377 field elements.
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
		frontend.Variable("0x894b84bdb19c99b174eef89446c8042b49d9d2a82fc46c4d653ebdcd127a9aa"),
		frontend.Variable("0xc6b7ff8356bd516fad4f06f4c5354bb1ea26d27b3e9b156e89f0c9ba9ea1163"),
		frontend.Variable("0xd03966afba794725c52dd8f7507a62b3441fb8608becf0b0cc077744ed99175"),
	}
	round += 1
	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x8c34d497d141ad73833b13ced2b8f457312a3ed8b5a6d9387f6efdc451260ac"),
		frontend.Variable("0x11e6eeea347fd87200953e431bb652bac5e86acc07849fcc34066fc43475cffe"),
		frontend.Variable("0xb9034e2459a594e1be61dc0359ee295ae75b00fdce16ef62f4d8ccd13ffb859"),
	}
	round += 1
	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x4b223f6f682ee44bf4a873f3213f089c3d177918571ad89bbd14dc41d6a24e6"),
		frontend.Variable("0x837100b8863659249a0f72e38804af3e1297893de888f0d9fec16cfba2ab82"),
		frontend.Variable("0xc81b73f232fa3111835446ea4cfc56e28be0582edfb0f83d4ebbefb278afbba"),
	}
	round += 1
	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0xb78e340840581b85f52728896d521caf8ae8cf427068415b04a53d27dc289b6"),
		frontend.Variable("0x574ee59fd4970e96a6614a64f18fa36a685c18580dbdf781438efbfa4b09514"),
		frontend.Variable("0x38f66ae633f3b619c8c56dc8229664af8206a45eb72d87f1ffd2476e4888072"),
	}
	round += 1

	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0xb49e75e262625b53ace4b7f65bb2c21939ffeef5972cea323bf413452bfdf72"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1
	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x1041c87189c3c09a68d02fa4987a40b64d8fc292b4e4bdfa6aa1625d4b4e347a"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1
	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x617005b62e4dcbb8498f7b5f43ead4675593ccc72cf8b2f4a01fa2e1da60b1a"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1
	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0xa1251b1b798a04e658b1434bd328d5f3ee68e1ac1bb6e817ea31475f0f47a56"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1
	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0xb336196b7d36dde674677dfba167bec7603a3c96bf20899a9d4c616f0ffa402"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1
	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x128e08a771214fc069a55f842eeb0a8c370a8c94cbbd573432466b555f9231f1"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1
	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0xc790be90ed5461394e69ff6624b1e65fbe25dc9daebfee6b6965a039eff3744"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1
	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0xb586c3356fa5d91c8bc23605141464545007477bcc96acbbe8efced6246e980"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1
	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0xa728798fadfc910fd1549526343488b5ee1de16c9471212c85b85892f5b60e4"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1
	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0xb88a3d215d130dfb3c39c7ed503303704b58e16d7710dfb5f9bf9e3d5a20e8d"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1
	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0xa1d326b6b608ad8565c3e8e7e7ccd497d4cca0ee291f9a73114b4e9824cfb69"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1
	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x57113400390d93f8389e1bec27e88e0793cd3949228717f795276915d4ab828"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1
	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x84a8a42dfee951df4471112d863f64d7d5460f046289b4421087d3869e1a1a4"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1
	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0xd23209a191a79b5e7228d9d19956724a256c57bbb7136be0864edd0a70ff5b6"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1
	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x6f851da6c82b3a1a672bd64a45143572b504037935f373bf7baf8299342cb26"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1
	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x7eaafe8322cc00fd21fba188b4e00ce5a7549316735482ff55f8de90f17492a"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1
	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0xa2c1b6cd105105347b6cccf1b0a75124a4e7232b12fb39925e7c2f776e5ba30"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1
	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0xce6cab1e12a67f98fc9705ffa96c8a10e4c11f29a31ce28273bf8b50c7e4729"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1
	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0xfd2ae97a893ddc5aabf968d4067b6e7da71e548bd744e13179410dd4ad40fe2"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1
	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0xc397b9593b7e3a15609549af9ee1c305ace3233a8b70d791d47d273091a197b"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1
	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x48e2850c540b39acc7bce93429d2bde169ec7249b3cf361bd3f7de3f51d576f"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1
	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0xc2d5af8414c6c7ce014f345fc6b0bd90d313d794f3274e7396b18eee353c6e1"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1
	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x5232e19ed5be0cc0a6f158edcca9fcdb53684db1379a6ccd0cd9b43e898cd1e"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1
	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x121d8e282bba81dc8a608140dde24856e4289abbc1cc213c85842db14a7392c3"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1
	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x11ac4b1250a86aa1cdb9b103d9bcc7d6ba641d012ef557ada2e571e27d241708"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1
	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x56a6c575f7a3ee274f91e6fca0233d3e4a9bb1eb3c58fb052af73acc8df2b7a"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1
	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0xbca1f27ae2e39fd568b543f19336d2d1003446982b00317eafb7a56bcd06730"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1
	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0xe9f191a928aa8c498873d150994e6bca51cdbdaf2285eccb2aaa93cc73291d"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1
	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x4465495bdea2589718a8f12ad7198273aea88c72442ddf8d879093cc51a7586"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1
	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x1040f9e259df7c4a09ed900afcee53107c7608b276477ae51b3b4bfd40e2b825"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1
	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x11d223e26d5c6ba13a8c4382a51f62d97cc553f9be8770470cbd248deda5044f"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1
	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x3bf579fa65a5e93fbd27d67791c493cecaa1c55b505c526b84c738b073e085e"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1
	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x7967b3d5778a590b6cc278493a64559445188c3cdb0224585c60603f73a6014"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1
	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0xbf4c86a238f1e63bde595027513d18e26fa557cb4ba00196159778578133cb0"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1
	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0xa582308f6a557cb37cb0a615659d7211f228a09f591fa0a4f28b7cb42b4bde8"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1
	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0xdcc13ae2b4c6179a435253fcbb275f8e4ee4c1cb0eae8d679b512a299a56dc8"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1
	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0xcf02a438c9896590f44512473a4dd39cbc1bde9a53f0b3db38fb6d2f18e91a8"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
		frontend.Variable("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}
	round += 1

	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x5c647cd7fc470cc99e170e20270423b8eee990919b1b09cfc4a386e6fe5a2ce"),
		frontend.Variable("0x6a3eee48a5ca08253fb4269241ed389e45ba8db152b8850de999b2de2c10257"),
		frontend.Variable("0xe4b0350a154112207e2eecfc173ad3896cf9a7d8942249c71bf318f329141e8"),
	}
	round += 1
	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x7e7370481cc29ffce69ba474f5655078ab875161563fbc9379890411996613b"),
		frontend.Variable("0x28d1224a254fc72827cd40c6e516f74b412cb9bffe167294ebdeda4f2dca32f"),
		frontend.Variable("0xedd071622a8d683a1ac9143eccbf8716b3dfe11fa0ae2aba3abe87d615de44a"),
	}
	round += 1
	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x10ba95e17edfec41ca46d94471f755059fe31b505746f9d5401c127cdc295aa3"),
		frontend.Variable("0x87f089986c09c923d0546aa9a950094fbf66086c5877be7495806dc6ff1e75e"),
		frontend.Variable("0x1881b97f72998e6c78f6fd491a33dedc163190de20923ab7b3198af285a9aa7"),
	}
	round += 1
	rc3[round] = [width]frontend.Variable{
		frontend.Variable("0x99c71834ef68ccc063eb2b57cf6967e2d5e08cdb32eafba0ddc659323b49a9e"),
		frontend.Variable("0xa4312710936ff86b44d9bbe51dd26faf32bdc6f774eac9dbcf1c96faba24394"),
		frontend.Variable("0x19e2b92497e2585e28fd0c5cbdad9c93faa238d34d5eb24a3e8e81ac9b5f343"),
	}
	round += 1
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
