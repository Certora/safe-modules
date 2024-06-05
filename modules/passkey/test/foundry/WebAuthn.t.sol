// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import "forge-std/console.sol";
import "../../contracts/libraries/WebAuthn.sol";
import {WebAuthn} from "../../contracts/libraries/WebAuthn.sol";

contract WebAuthnTest is Test {
    using WebAuthn for bytes32;

    // run with forge test --mt test_encodeClientDataJsonDifferentInputResultsInDifferentOutput
    function test_encodeClientDataJsonDifferentInputResultsInDifferentOutput(bytes32 challenge1,
        string calldata clientDataFields1, bytes32 challenge2,
        string calldata clientDataFields2) public {
            string memory clientDataJson1 = challenge1.encodeClientDataJson(clientDataFields1);
            string memory clientDataJson2 = challenge2.encodeClientDataJson(clientDataFields2);
            if(challenge1 != challenge2 || keccak256(abi.encodePacked(clientDataFields1)) != keccak256(abi.encodePacked(clientDataFields2))){
                vm.assertNotEq(clientDataJson1, clientDataJson2);
            } 
    }

    function getSha256(bytes memory input) public view returns (bytes32 digest) {
        return WebAuthn._sha256(input);
    }

    function compareStrings(string memory str1, string memory str2) public view returns (bool) {
        bytes memory str1Bytes = bytes(str1);
        bytes memory str2Bytes = bytes(str2);
        return getSha256(str1Bytes) == getSha256(str2Bytes);
    }

    // run with forge test --mt // test_encodeClientDataJsonDifferentInputResultsInDifferentOutputProver
    function test_encodeClientDataJsonDifferentInputResultsInDifferentOutputProver(
        string calldata clientDataFields
    ) public {
        bytes32 challenge1 = bytes32(uint256(0xd));
        bytes32 challenge2 = bytes32(uint256(0xf));
        string memory clientDataJson1 = challenge1.encodeClientDataJson(clientDataFields);
        string memory clientDataJson2 = challenge2.encodeClientDataJson(clientDataFields);

        vm.assertFalse(compareStrings(clientDataJson1, clientDataJson2));
    }
}
