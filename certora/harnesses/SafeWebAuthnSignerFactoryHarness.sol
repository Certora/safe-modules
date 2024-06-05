// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity >=0.8.0;

import {SafeWebAuthnSignerFactory} from "../../modules/passkey/contracts/SafeWebAuthnSignerFactory.sol";
import {P256} from "../../modules/passkey/contracts/libraries/P256.sol";
import {SafeWebAuthnSignerProxy} from "../../modules/passkey/contracts/SafeWebAuthnSignerProxy.sol";

contract SafeWebAuthnSignerFactoryHarness is SafeWebAuthnSignerFactory {
   
    //Harness
    function hasNoCode(address account) external view returns (bool result) {
        // solhint-disable-next-line no-inline-assembly
        return SafeWebAuthnSignerFactory._hasNoCode(account);
    }

    function createAndVerify(
        bytes32 message,
        bytes calldata signature,
        uint256 x,
        uint256 y,
        P256.Verifiers verifiers
    ) external returns (bytes4 magicValue) {
        address signer = this.createSigner(x, y, verifiers);

        bytes memory data = abi.encodeWithSignature("isValidSignature(bytes32,bytes)", message, signature);

        // Use low-level call to invoke isValidSignature on the signer address
        (bool success, bytes memory result) = signer.staticcall(data);
        require(success);
        magicValue = abi.decode(result, (bytes4));
    }

    function getSignerHarnessed(uint256 x, uint256 y, P256.Verifiers verifiers) public view returns (uint256 value) {
        bytes32 codeHash = keccak256(
            abi.encodePacked(
                type(SafeWebAuthnSignerProxy).creationCode,
                "01234567891011121314152546",
                uint256(uint160(address(SINGLETON))),
                x,
                y,
                uint256(P256.Verifiers.unwrap(verifiers))
            )
        );
        value = uint256(keccak256(abi.encodePacked(hex"ff", address(this), bytes32(0), codeHash)));
    }
    function castToAddress(uint256 value) public pure returns (address addr){
        addr = address(uint160(value));
    }
}