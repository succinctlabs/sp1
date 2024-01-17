#![no_main]

use hex_literal::hex;
use serde_json;
use ssz_rs::prelude::*;
use std::hint::black_box;
use std::str::FromStr;

extern crate curta_zkvm;

curta_zkvm::entrypoint!(main);

mod beacon;
mod proof;

use beacon::*;
use proof::is_valid_merkle_big_branch;

fn main() {
    // Prove 0th withdrawal (validator 795049) from mainnet slot 7857409
    // Beacon root -> header -> validators root and withdrawals root -> validator and withdrawal
    header_proof();
    withdrawals_root_proof();
    withdrawal_proof();
    validators_root_proof();
    validator_proof();
}

fn branch_from_hex(s: Vec<&str>) -> Vec<Node> {
    s.iter()
        .map(|hex: &&str| node_from_hex(*hex))
        .collect::<Vec<Node>>()
}

fn node_from_hex(s: &str) -> Node {
    Node::try_from(&hex::decode(s).unwrap()[..]).unwrap()
}

fn withdrawals_root_proof() {
    let leaf = Node::try_from(
        hex!("5cc52fb136d9ff526f071f8f87d44c3f35ff5dc973371a2c3613d8ecc53bfcd4").as_slice(),
    )
    .unwrap();
    let branch = branch_from_hex(vec![
        "0000000000000000000000000000000000000000000000000000000000000000",
        "8d72069921728c6688441d7cb5dab79812429013ac09311d5456aa61b770084d",
        "f43b91870f20fa578621b1921572b2497f1800a0b46ba5fcd62b55b625484a62",
        "0e7b89b1f002a34b400823b237859832c120a514d21f30de6c41cd4693fbc82a",
        "1912b846656eeebcbe7f442b1e790abfd786a87c51f5065c9313e58d2a982ca5",
        "336488033fe5f3ef4ccc12af07b9370b92e553e35ecb4a337a1b1c0e4afe1e0e",
        "db56114e00fdd4c1f85c892bf35ac9a89289aaecb1ebd0a96cde606a748b5d71",
        "8841ee1abbf9a4767cafd94441333031d3a72774bbb5da4d848e1fec08a840e6",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b",
        "3ca168014d8da18c223f9f3cbbad902cd2ffabaeef25d3ff32b0d51984231409",
    ]);
    let depth = 11;
    let index = 3230;
    let root = node_from_hex("88d257af10bc873ab8e41bfb9fd51be55249f78549ea0dbaa0c2deda979368e7");
    let valid = is_valid_merkle_branch(&leaf, branch.iter(), depth, index, &root);
    println!("withdrawals root valid: {}", valid);
}

fn withdrawal_proof() {
    let mut withdrawal = Withdrawal {
        index: 26081110,
        validator_index: 795049,
        address: ExecutionAddress::try_from(
            hex!("4bbeae4ca5c6f79a1bc7db315bb6f2c90ebbb4cc").to_vec(),
        )
        .unwrap(),
        amount: 17122745,
    };

    let leaf = withdrawal.hash_tree_root().unwrap();
    let branch = black_box(vec![
        "cf4999288497e7a3ee17c8251a26ac3ae91bc6b7ac5a2ad42df15807d4aaa99d",
        "cad0401190b985bede55534962ab9700e57f95d7da447969e842507404427e39",
        "a98e59035f016b68eabde1d90e7e617dac80b0ec72931f30261e3c53ae9d1999",
        "10de9d131acb9a2dba0843ce3dc101116d3043f4aa1a3f8f5c0b053d7d9c7d46",
        "1000000000000000000000000000000000000000000000000000000000000000",
    ])
    .iter()
    .map(|hex: &&str| node_from_hex(*hex))
    .collect::<Vec<Node>>();
    let depth = black_box(5);
    let index = black_box(32);
    let root = black_box(node_from_hex(
        "5cc52fb136d9ff526f071f8f87d44c3f35ff5dc973371a2c3613d8ecc53bfcd4",
    ));
    let valid = black_box(is_valid_merkle_branch(
        &leaf,
        branch.iter(),
        depth,
        index,
        &root,
    ));
    println!("withdrawal valid: {}", valid);
}

fn header_proof() {
    let header_json = r#"{"slot":"7857409","proposer_index":"440701","parent_root":"0x34d8f1f1afe3c688cdc9a4b94bc50ffadc065df2156a60606c8e629a4ea55add","state_root":"0x98c0fd5c235d54fc828bf4ec3d8a2985da058a2678fed5dd8c3231145dd7c156","body_root":"0xcde46fe6886db13475b7fec79e210911a9a26d589e66ac05985e95c50975ac30"}"#;

    let mut header: BeaconBlockHeader = serde_json::from_str(header_json).unwrap();
    let header_root = header.hash_tree_root().unwrap();
    println!("header root: {:?}", header_root);
}

fn validators_root_proof() {
    let leaf = Node::try_from(
        hex!("8ada0d639d94919c8a8aa62f13bbf5f0a0bf3e4340aa01679e533a4f68a54dc0").as_slice(),
    )
    .unwrap();
    let branch = vec![
        "b27b100000000000000000000000000000000000000000000000000000000000",
        "e5da071085e819357fd4a416416e21fe9a679b382da47c5acb3abe5b756c1958",
        "2ed0e7ad478ad9368bf451f3df6ef082094e9dd2d830c441fae41ebfebc84dc4",
        "45f160b40030ff5f85164e1cae445f13360c820f5194f38d3ba7f0cad08cf573",
        "e6e49e7d4ebc221a8cc193b623a260de6c91fa8382e40dbd50ce6c898252545d",
        "34d8f1f1afe3c688cdc9a4b94bc50ffadc065df2156a60606c8e629a4ea55add",
        "9d1b8e00a8c76b185d2f4322432eee0d5797f1da0c4b9a9ab4d9ba04460b3ab9",
        "d2c3e8005d0f60900b02e681738404360529c5f28c34160abc3e639c651ec391",
    ]
    .iter()
    .map(|hex: &&str| node_from_hex(*hex))
    .collect::<Vec<Node>>();
    let depth = 8;
    let index = 363;
    let root = node_from_hex("88d257af10bc873ab8e41bfb9fd51be55249f78549ea0dbaa0c2deda979368e7");
    let valid = is_valid_merkle_branch(&leaf, branch.iter(), depth, index, &root);
    println!("validators root valid: {}", valid);
}

fn validator_proof() {
    let mut validator = Validator {
            pubkey: Vector::try_from(hex!("b005012bfc4a0d6fd04d0479724b7aeb64462d558bb9b731e47c6d0b5999a12b77f8a4f7724aa87aaf586a5bfc831c80").to_vec()).unwrap(),
            withdrawal_credentials: node_from_hex("0100000000000000000000004bbeae4ca5c6f79a1bc7db315bb6f2c90ebbb4cc"),
            effective_balance: 32000000000,
            slashed: false,
            activation_eligibility_epoch: 210209,
            activation_epoch: 219962,
            exit_epoch: 18446744073709551615,
            withdrawable_epoch: 18446744073709551615,
    };

    let leaf = validator.hash_tree_root().unwrap();
    let branch = black_box(vec![
        "e075356f0de5a8ada345cfbc659e02600c381c2de2e62dbce0ff1532f3c58d07",
        "321356d9f54c30b2ef61708679aeb3dd2747e6c2502d566fb04f7c404b4c76d2",
        "ed8f2e00df064fb7eb985a24825d94d44c265955bd25400a31167202b42c96c7",
        "bab082567b013beef822eb0555ff721c9790dfccde04d5905053bf88eb3b1d91",
        "f95a768cd1fe077a8af4e44ec1a6eb3913df1ea1d5c12a3a2d1381b9fd5000ec",
        "d94aa0337fc162c0ca7d3eaf2a06cbe98fab5f5fd44a5116db9613930906c861",
        "040d7a1711a2df276af4b44196786779055b8beb4d161017a31f0ea121084913",
        "1d3507adbf5e08b29af66b27fb11cf0116965c3d1c72599ee1e8447aa0d7a831",
        "7ef44a0663996c241ccfe000c247568cfe2ac95d2ff0181818e13e1d25b5d82b",
        "be3d37cbfcc80f6cb90affd827148b8ec4a84999f63e3a541728269dd2b81d74",
        "742bfcc2c2e291e770a2f0f957e4a73bc5f0e6a4b3ac920a671c4bb63f4ad06f",
        "d54b2a971f8cfd672117ce8399f42a58e0a5db5ae8a4158f0102628c700fc433",
        "7313386734714b621b6e0b6d287b4f68c0a411a744bff857a43b492ed8c0f938",
        "74c0164db9880076c4c9142f3acc8689e322342a61886c7129f75b00ac8a80c1",
        "3ce51b360e4a8a13823be7b4a8b2b41e779b1f68c79fbf5d53f1e527d054ce57",
        "b0ba4d4679795524aa4336728c637fc130fdebde617b4ed082d04e5cc82371e3",
        "21a52516163bb5f063a240b59557bbf15225fe3cdd4044a446ffe2c7474fa512",
        "679adcc02052f3ae34d1dce4cb01120ec9fa67a7ee6a43d3eeea993c01266245",
        "ad33934639a9aa33b5ba84b4f1875b1e4e1230d75b1127eb33bd8ae7b8cb5d7c",
        "84c2ac0410a9b555e8ab56138015c847037f837776a82dcfbf7a5ceebe6660d9",
        "cddba7b592e3133393c16194fac7431abf2f5485ed711db282183c819e08ebaa",
        "8a8d7fe3af8caa085a7639a832001457dfb9128a8061142ad0335629ff23ff9c",
        "feb3c337d7a51a6fbf00b9e34c52e1c9195c969bd4e7a0bfd51d5c5bed9c1167",
        "e71f0aa83cc32edfbefa9f4d3e0174ca85182eec9f3a09f6a6c0df6377a510d7",
        "31206fa80a50bb6abe29085058f16212212a60eec8f049fecb92d8c8e0a84bc0",
        "21352bfecbeddde993839f614c3dac0a3ee37543f9b412b16199dc158e23b544",
        "619e312724bb6d7c3153ed9de791d764a366b389af13c58bf8a8d90481a46765",
        "7cdd2986268250628d0c10e385c58c6191e6fbe05191bcc04f133f2cea72c1c4",
        "848930bd7ba8cac54661072113fb278869e07bb8587f91392933374d017bcbe1",
        "8869ff2c22b28cc10510d9853292803328be4fb0e80495e8bb8d271f5b889636",
        "b5fe28e79f1b850f8658246ce9b6a1e7b49fc06db7143e8fe0b4f2b0c5523a5c",
        "985e929f70af28d0bdd1a90a808f977f597c7c778c489e98d3bd8910d31ac0f7",
        "c6f67e02e6e4e1bdefb994c6098953f34636ba2b6ca20a4721d2b26a886722ff",
        "1c9a7e5ff1cf48b4ad1582d3f4e4a1004f3b20d8c5a2b71387a4254ad933ebc5",
        "2f075ae229646b6f6aed19a5e372cf295081401eb893ff599b3f9acc0c0d3e7d",
        "328921deb59612076801e8cd61592107b5c67c79b846595cc6320c395b46362c",
        "bfb909fdb236ad2411b4e4883810a074b840464689986c3f8a8091827e17c327",
        "55d8fb3687ba3ba49f342c77f5a1f89bec83d811446e1a467139213d640b6a74",
        "f7210d4f8e7e1039790e7bf4efa207555a10a6db1dd4b95da313aaa88b88fe76",
        "ad21b516cbc645ffe34ab5de1c8aef8cd4e7f8d2b51e8e1456adc7563cda206f",
        "e0f50f0000000000000000000000000000000000000000000000000000000000",
    ])
    .iter()
    .map(|hex: &&str| node_from_hex(*hex))
    .collect::<Vec<Node>>();
    let depth = black_box(41);
    let index = alloy_primitives::U256::from_str("2199024050601").unwrap();
    let root = black_box(node_from_hex(
        "8ada0d639d94919c8a8aa62f13bbf5f0a0bf3e4340aa01679e533a4f68a54dc0",
    ));
    let valid = black_box(is_valid_merkle_big_branch(
        &leaf,
        branch.iter(),
        depth,
        index,
        &root,
    ));
    println!("validator valid: {}", valid);
}
