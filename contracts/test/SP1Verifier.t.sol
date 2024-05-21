// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {SP1Verifier} from "../src/SP1Groth16Verifier.sol";

contract SP1VerifierTest is Test {
    SP1Verifier public sp1Verifier;

    function setUp() public {
        sp1Verifier = new SP1Verifier();
    }
}
