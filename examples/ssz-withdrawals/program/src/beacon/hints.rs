use crate::beacon::types::*;
use crate::beacon::utils::{branch_from_bytes, node_from_bytes};
use hex_literal::hex;
use ssz_rs::prelude::*;
use std::hint::black_box;

/// Returns the beaacon block's withdrawals root and a corresponding SSZ merkle proof.
pub fn withdrawals_root_proof(_block_root: Node) -> (Node, Vec<Node>) {
    let leaf =
        node_from_bytes(hex!("5cc52fb136d9ff526f071f8f87d44c3f35ff5dc973371a2c3613d8ecc53bfcd4"));
    let branch = branch_from_bytes(
        [
            hex!("0000000000000000000000000000000000000000000000000000000000000000"),
            hex!("8d72069921728c6688441d7cb5dab79812429013ac09311d5456aa61b770084d"),
            hex!("f43b91870f20fa578621b1921572b2497f1800a0b46ba5fcd62b55b625484a62"),
            hex!("0e7b89b1f002a34b400823b237859832c120a514d21f30de6c41cd4693fbc82a"),
            hex!("1912b846656eeebcbe7f442b1e790abfd786a87c51f5065c9313e58d2a982ca5"),
            hex!("336488033fe5f3ef4ccc12af07b9370b92e553e35ecb4a337a1b1c0e4afe1e0e"),
            hex!("db56114e00fdd4c1f85c892bf35ac9a89289aaecb1ebd0a96cde606a748b5d71"),
            hex!("8841ee1abbf9a4767cafd94441333031d3a72774bbb5da4d848e1fec08a840e6"),
            hex!("0000000000000000000000000000000000000000000000000000000000000000"),
            hex!("f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b"),
            hex!("3ca168014d8da18c223f9f3cbbad902cd2ffabaeef25d3ff32b0d51984231409"),
        ]
        .as_slice(),
    );

    (leaf, branch)
}

/// Given a block root and index [0, 16), returns the withdrawal and a corresponding SSZ proof.
pub fn withdrawal_proof(_block_root: Node, _index: u32) -> (Withdrawal, Vec<Node>) {
    let withdrawal = Withdrawal {
        index: 26081110,
        validator_index: 795049,
        address: ExecutionAddress::try_from(
            hex!("4bbeae4ca5c6f79a1bc7db315bb6f2c90ebbb4cc").to_vec(),
        )
        .unwrap(),
        amount: 17122745,
    };

    let branch = branch_from_bytes(black_box(
        [
            hex!("cf4999288497e7a3ee17c8251a26ac3ae91bc6b7ac5a2ad42df15807d4aaa99d"),
            hex!("cad0401190b985bede55534962ab9700e57f95d7da447969e842507404427e39"),
            hex!("a98e59035f016b68eabde1d90e7e617dac80b0ec72931f30261e3c53ae9d1999"),
            hex!("10de9d131acb9a2dba0843ce3dc101116d3043f4aa1a3f8f5c0b053d7d9c7d46"),
            hex!("1000000000000000000000000000000000000000000000000000000000000000"),
        ]
        .as_slice(),
    ));

    (withdrawal, branch)
}

/// Returns the corresponding beacon block header.
pub fn beacon_header_proof(_block_root: Node) -> BeaconBlockHeader {
    BeaconBlockHeader {
        slot: 8225000,
        proposer_index: 980811,
        parent_root: node_from_bytes(hex!(
            "6a8edd0d02c6195037bfab129783fb9847d88e7587a3b097fdc4eb5cb0da7a16"
        )),
        state_root: node_from_bytes(hex!(
            "02b054e25cfa96a82e7d133c0f469dcfd1661fd75203a612f17dfe2f4bdb956a"
        )),
        body_root: node_from_bytes(hex!(
            "ca1a1e5f480a739b8e276db2f67f8ea399955604ad1479d748bd6912029e9dd8"
        )),
    }
}

/// Returns the beacon block's validators root and a corresponding SSZ merkle proof.
pub fn validators_root_proof(_block_root: Node) -> (Node, Vec<Node>) {
    let leaf = Node::try_from(
        hex!("8ada0d639d94919c8a8aa62f13bbf5f0a0bf3e4340aa01679e533a4f68a54dc0").as_slice(),
    )
    .unwrap();
    let branch = branch_from_bytes(
        [
            hex!("b27b100000000000000000000000000000000000000000000000000000000000"),
            hex!("e5da071085e819357fd4a416416e21fe9a679b382da47c5acb3abe5b756c1958"),
            hex!("2ed0e7ad478ad9368bf451f3df6ef082094e9dd2d830c441fae41ebfebc84dc4"),
            hex!("45f160b40030ff5f85164e1cae445f13360c820f5194f38d3ba7f0cad08cf573"),
            hex!("e6e49e7d4ebc221a8cc193b623a260de6c91fa8382e40dbd50ce6c898252545d"),
            hex!("34d8f1f1afe3c688cdc9a4b94bc50ffadc065df2156a60606c8e629a4ea55add"),
            hex!("9d1b8e00a8c76b185d2f4322432eee0d5797f1da0c4b9a9ab4d9ba04460b3ab9"),
            hex!("d2c3e8005d0f60900b02e681738404360529c5f28c34160abc3e639c651ec391"),
        ]
        .as_slice(),
    );

    (leaf, branch)
}

/// Returns the corresponding validator and SSZ proof.
pub fn validator_proof(_block_root: Node, _index: u64) -> (Validator, Vec<Node>) {
    let validator = Validator {
        pubkey: Vector::try_from(hex!("b005012bfc4a0d6fd04d0479724b7aeb64462d558bb9b731e47c6d0b5999a12b77f8a4f7724aa87aaf586a5bfc831c80").to_vec()).unwrap(),
        withdrawal_credentials: node_from_bytes(hex!("0100000000000000000000004bbeae4ca5c6f79a1bc7db315bb6f2c90ebbb4cc")),
        effective_balance: 32000000000,
        slashed: false,
        activation_eligibility_epoch: 210209,
        activation_epoch: 219962,
        exit_epoch: 18446744073709551615,
        withdrawable_epoch: 18446744073709551615,
    };

    let branch = branch_from_bytes(
        [
            hex!("e075356f0de5a8ada345cfbc659e02600c381c2de2e62dbce0ff1532f3c58d07"),
            hex!("321356d9f54c30b2ef61708679aeb3dd2747e6c2502d566fb04f7c404b4c76d2"),
            hex!("ed8f2e00df064fb7eb985a24825d94d44c265955bd25400a31167202b42c96c7"),
            hex!("bab082567b013beef822eb0555ff721c9790dfccde04d5905053bf88eb3b1d91"),
            hex!("f95a768cd1fe077a8af4e44ec1a6eb3913df1ea1d5c12a3a2d1381b9fd5000ec"),
            hex!("d94aa0337fc162c0ca7d3eaf2a06cbe98fab5f5fd44a5116db9613930906c861"),
            hex!("040d7a1711a2df276af4b44196786779055b8beb4d161017a31f0ea121084913"),
            hex!("1d3507adbf5e08b29af66b27fb11cf0116965c3d1c72599ee1e8447aa0d7a831"),
            hex!("7ef44a0663996c241ccfe000c247568cfe2ac95d2ff0181818e13e1d25b5d82b"),
            hex!("be3d37cbfcc80f6cb90affd827148b8ec4a84999f63e3a541728269dd2b81d74"),
            hex!("742bfcc2c2e291e770a2f0f957e4a73bc5f0e6a4b3ac920a671c4bb63f4ad06f"),
            hex!("d54b2a971f8cfd672117ce8399f42a58e0a5db5ae8a4158f0102628c700fc433"),
            hex!("7313386734714b621b6e0b6d287b4f68c0a411a744bff857a43b492ed8c0f938"),
            hex!("74c0164db9880076c4c9142f3acc8689e322342a61886c7129f75b00ac8a80c1"),
            hex!("3ce51b360e4a8a13823be7b4a8b2b41e779b1f68c79fbf5d53f1e527d054ce57"),
            hex!("b0ba4d4679795524aa4336728c637fc130fdebde617b4ed082d04e5cc82371e3"),
            hex!("21a52516163bb5f063a240b59557bbf15225fe3cdd4044a446ffe2c7474fa512"),
            hex!("679adcc02052f3ae34d1dce4cb01120ec9fa67a7ee6a43d3eeea993c01266245"),
            hex!("ad33934639a9aa33b5ba84b4f1875b1e4e1230d75b1127eb33bd8ae7b8cb5d7c"),
            hex!("84c2ac0410a9b555e8ab56138015c847037f837776a82dcfbf7a5ceebe6660d9"),
            hex!("cddba7b592e3133393c16194fac7431abf2f5485ed711db282183c819e08ebaa"),
            hex!("8a8d7fe3af8caa085a7639a832001457dfb9128a8061142ad0335629ff23ff9c"),
            hex!("feb3c337d7a51a6fbf00b9e34c52e1c9195c969bd4e7a0bfd51d5c5bed9c1167"),
            hex!("e71f0aa83cc32edfbefa9f4d3e0174ca85182eec9f3a09f6a6c0df6377a510d7"),
            hex!("31206fa80a50bb6abe29085058f16212212a60eec8f049fecb92d8c8e0a84bc0"),
            hex!("21352bfecbeddde993839f614c3dac0a3ee37543f9b412b16199dc158e23b544"),
            hex!("619e312724bb6d7c3153ed9de791d764a366b389af13c58bf8a8d90481a46765"),
            hex!("7cdd2986268250628d0c10e385c58c6191e6fbe05191bcc04f133f2cea72c1c4"),
            hex!("848930bd7ba8cac54661072113fb278869e07bb8587f91392933374d017bcbe1"),
            hex!("8869ff2c22b28cc10510d9853292803328be4fb0e80495e8bb8d271f5b889636"),
            hex!("b5fe28e79f1b850f8658246ce9b6a1e7b49fc06db7143e8fe0b4f2b0c5523a5c"),
            hex!("985e929f70af28d0bdd1a90a808f977f597c7c778c489e98d3bd8910d31ac0f7"),
            hex!("c6f67e02e6e4e1bdefb994c6098953f34636ba2b6ca20a4721d2b26a886722ff"),
            hex!("1c9a7e5ff1cf48b4ad1582d3f4e4a1004f3b20d8c5a2b71387a4254ad933ebc5"),
            hex!("2f075ae229646b6f6aed19a5e372cf295081401eb893ff599b3f9acc0c0d3e7d"),
            hex!("328921deb59612076801e8cd61592107b5c67c79b846595cc6320c395b46362c"),
            hex!("bfb909fdb236ad2411b4e4883810a074b840464689986c3f8a8091827e17c327"),
            hex!("55d8fb3687ba3ba49f342c77f5a1f89bec83d811446e1a467139213d640b6a74"),
            hex!("f7210d4f8e7e1039790e7bf4efa207555a10a6db1dd4b95da313aaa88b88fe76"),
            hex!("ad21b516cbc645ffe34ab5de1c8aef8cd4e7f8d2b51e8e1456adc7563cda206f"),
            hex!("e0f50f0000000000000000000000000000000000000000000000000000000000"),
        ]
        .as_slice(),
    );

    (validator, branch)
}

/// Return the historical summary root containing the target slot and a corresponding SSZ proof.
///
/// The target slot must be at most (source_slot - 8192).
pub fn historical_far_slot_proof(_block_root: Node, _target_slot: u64) -> (Node, Vec<Node>) {
    // Block root -> historical summary root
    let leaf =
        node_from_bytes(hex!("1d52ab18adbab483661ee3dd7ebc62691abe30c1ac619a120a4d3050ec0f7c4b"));
    let branch = branch_from_bytes(
        [
            hex!("71d67d25484adcd645fc49c83f48a44b2f95c6215356a6f858549ef5ce0fd141"),
            hex!("7edb31a2db983bbef421217131d3073e1c1c34cafad08374f39c8b51850ca907"),
            hex!("7bd21503c7a2dc1c39f132639fd6a28aa2fad590d0b0b14a1b4b177b39f69b1c"),
            hex!("c2989830254dad6751f97da47fcdf8a6cca5179e5b8a1b000562382b9523808d"),
            hex!("13f3e6cee244b2a1854f29254223e898db082331faa7a04363eb7ab779f44166"),
            hex!("1b1f565fde7046ec5164668459a1906eb9239d83d62869f97fdb0051b3986615"),
            hex!("a8fb6dc98b7b638c5f0f39134e8b545dd7b1f5f924fda80247eb432bb098d53b"),
            hex!("8793464b9aec0216b2b2fd8721d5377602722287b548a4370cb44654233752e0"),
            hex!("26846476fd5fc54a5d43385167c95144f2643f533cc85bb9d16b782f8d7db193"),
            hex!("506d86582d252405b840018792cad2bf1259f1ef5aa5f887e13cb2f0094f51e1"),
            hex!("ffff0ad7e659772f9534c195c815efc4014ef1e1daed4404c06385d11192e92b"),
            hex!("6cf04127db05441cd833107a52be852868890e4317e6a02ab47683aa75964220"),
            hex!("b7d05f875f140027ef5118a2247bbb84ce8f2f0f1123623085daf7960c329f5f"),
            hex!("df6af5f5bbdb6be9ef8aa618e4bf8073960867171e29676f8b284dea6a08a85e"),
            hex!("b58d900f5e182e3c50ef74969ea16c7726c549757cc23523c369587da7293784"),
            hex!("d49a7502ffcfb0340b1d7885688500ca308161a7f96b62df9d083b71fcc8f2bb"),
            hex!("8fe6b1689256c0d385f42f5bbe2027a22c1996e110ba97c171d3e5948de92beb"),
            hex!("8d0d63c39ebade8509e0ae3c9c3876fb5fa112be18f905ecacfecb92057603ab"),
            hex!("95eec8b2e541cad4e91de38385f2e046619f54496c2382cb6cacd5b98c26f5a4"),
            hex!("f893e908917775b62bff23294dbbe3a1cd8e6cc1c35b4801887b646a6f81f17f"),
            hex!("cddba7b592e3133393c16194fac7431abf2f5485ed711db282183c819e08ebaa"),
            hex!("8a8d7fe3af8caa085a7639a832001457dfb9128a8061142ad0335629ff23ff9c"),
            hex!("feb3c337d7a51a6fbf00b9e34c52e1c9195c969bd4e7a0bfd51d5c5bed9c1167"),
            hex!("e71f0aa83cc32edfbefa9f4d3e0174ca85182eec9f3a09f6a6c0df6377a510d7"),
            hex!("f600000000000000000000000000000000000000000000000000000000000000"),
            hex!("13d8050000000000000000000000000000000000000000000000000000000000"),
            hex!("431f12da5c99f901a543ca43ce3bf81d27aa2ca768dff91a57f4f7315e58ed34"),
            hex!("db56114e00fdd4c1f85c892bf35ac9a89289aaecb1ebd0a96cde606a748b5d71"),
            hex!("7065b5a85d89a8283552e82ee1e2638930cb77006062b2e0c1ef1a0d565d3b80"),
            hex!("12c7dbcbe2f85d52225951cc7581dc333c64eb538a4757552763d986f696ac15"),
            hex!("6a8edd0d02c6195037bfab129783fb9847d88e7587a3b097fdc4eb5cb0da7a16"),
            hex!("2766cb64d6adc5d69310000d535c140372ff879bc9dee329db746de3665c6b10"),
            hex!("e53131a68915218beddb79d3233e18e208775b90f32457414253f88e5e7320fa"),
        ]
        .as_slice(),
    );
    (leaf, branch)
}

/// Given a block root and target slot, return the target block root and a corresponding SSZ merkle
/// proof from historical summary root to target block root. The target slot must be at most
/// (source_slot - 8192).
pub fn historical_far_slot_blockroot_proof(
    _block_root: Node,
    _target_slot: u64,
) -> (Node, Vec<Node>) {
    let leaf =
        node_from_bytes(hex!("baa0d6d6383b6c227a59bd739d6adda29db2bbebc7db7a1d33f76d713c25be92"));
    let branch = branch_from_bytes(
        [
            hex!("c1335f53786cb473466d9e876f516e6fcf0c92fc584f1b04e382d5ff97a079a1"),
            hex!("3d97b9db50d76b323da4c6158627655cc08f312d20fa87891fe920f573e4dd0f"),
            hex!("bde4d4740ab0e58de6b544b0a07afa84dbcfaaf44de9622fed066ac4d1cc3528"),
            hex!("0d11c3f316880e9b435329f1614a5b0352aac1d6380394082b4c3efb3257aed2"),
            hex!("f1c253201bf508628075aa2c22de836695e488706491aa18f5791dac22a4945f"),
            hex!("27e1509081c6dce997920310354ea7b761ad9d4769d1d7c08af9dca9b6a8c5a4"),
            hex!("ac2097ec57fa31b30c79a6a9c992c70981ecbe28094f6fb093deeb036484a979"),
            hex!("67b3ddc88691307694988dd9a00d7843c6f5ac472b8de33dbbb5e6b9782d12a3"),
            hex!("3991d8ed56935aa73979411a92de0f76a48605f4eb3bdff3a0a8f3537856a512"),
            hex!("3506c644cad38ea2ff4c047350ceabaefed7459f643613458b99c2ff0417c23f"),
            hex!("018eeb10177703946d889cc270df7681c9239d6affd88edd123cef235cf95648"),
            hex!("0f43d0bd83d6ce190650d5453d89a61b211ea7893634760a7d143e212de2e24b"),
            hex!("df4ca4136a2adad654f3614629ee0845cb4059f7fbb1ecfc6e278e0914510201"),
            hex!("9b3b8a195299c1fbcbbb0e526cbb0f831c7641170d21ff013df86c3e94db49b4"),
        ]
        .as_slice(),
    );
    (leaf, branch)
}

/// Returns withdrawal slots, withdrawal indexes, and validator indexes that match the given
/// withdrawal address.
pub fn withdrawals_range(
    _block_root: Node,
    _start_slot: u64,
    _end_slot: u64,
    _withdrawal_address: &ExecutionAddress,
) -> (Vec<(u64, Vec<u32>)>, Vec<u64>) {
    (
        vec![
            (7855804, vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]),
            (7855805, vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]),
            (7855806, vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]),
        ],
        vec![795049, 795050, 795051],
    )
}
