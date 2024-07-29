// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.20;

import {ISafe} from "../../modules/passkey/contracts/interfaces/ISafe.sol";
import {P256} from "../../modules/passkey/contracts/libraries/WebAuthn.sol";

contract SafeMockContract is ISafe {

    struct Signer {
        uint256 x;
        uint256 y;
        P256.Verifiers verifiers;
    }

    address public delegateCallMe;

    function setup(
        address[] calldata owners,
        uint256 threshold,
        address to,
        bytes calldata data,
        address fallbackHandler,
        address paymentToken,
        uint256 payment,
        address payable paymentReceiver
    ) external {}

    // copied from https://github.com/safe-global/safe-smart-account/blob/main/contracts/common/StorageAccessible.sol
    /**
     * @notice Reads `length` bytes of storage in the currents contract
     * @param offset - the offset in the current contract's storage in words to start reading from
     * @param length - the number of words (32 bytes) of data to read
     * @return the bytes that were read.
     */
    function getStorageAt(uint256 offset, uint256 length) public view returns (bytes memory) {
        bytes memory result = new bytes(3 * 32);
        return result;
        
        // bytes memory result = new bytes(length * 32);
        // for (uint256 index = 0; index < length; index++) {
        //     /* solhint-disable no-inline-assembly */
        //     /// @solidity memory-safe-assembly
        //     assembly {
        //         let word := sload(add(offset, index))
        //         mstore(add(add(result, 0x20), mul(index, 0x20)), word)
        //     }
        //     /* solhint-enable no-inline-assembly */
        // }
        // return result;
    }

    function delegatecallIsValidSignatureData(bytes memory data, bytes calldata signature)
        public
        returns (bytes4 magicValue) {
        
        (bool success, bytes memory result) = delegateCallMe.delegatecall(
            abi.encodeWithSignature("isValidSignature(bytes,bytes)", data, signature)
        );
        require(success, "delegatecallIsValidSignatureData failed");
        return bytes4(result);
    }

    function delegatecallIsValidSignatureMessage(bytes32 message, bytes calldata signature)
        public returns (bytes4 magicValue) {
        
        (bool success, bytes memory result) = delegateCallMe.delegatecall(
            abi.encodeWithSignature("isValidSignature(bytes32,bytes)", message, signature)
        );
        require(success, "delegatecallIsValidSignatureMessage failed");
        return bytes4(result);
    }

    function delegatecallConfigure(Signer memory signer) public {

        (bool success, bytes memory result) = delegateCallMe.delegatecall(
            abi.encodeWithSignature("configure(uint256,uint256,uint176)", signer.x, signer.y, signer.verifiers)
        );
        require(success, "delegatecallConfigure failed");
    }

}