using SafeWebAuthnSignerProxy as SafeWebAuthnSignerProxy;
using SafeWebAuthnSignerSingleton as SafeWebAuthnSignerSingleton;

// This is the same MAGIC_VALUE constant used in ERC1271.
definition MAGIC_VALUE() returns bytes4 = to_bytes4(0x1626ba7e);

methods {
    function authenticate(bytes32, bytes) external returns (bytes4) envfree;
    function _.verifySignatureAllowMalleability(address verifier, bytes32 message, uint256 r, uint256 s, uint256 x, uint256 y) internal => cvlP256Verify(verifier, message, r, s, x, y) expect bool;
    function _._ external => DISPATCH [
        SafeWebAuthnSignerProxy._
    ] default NONDET;
}

ghost mapping(address => mapping(bytes32 => mapping(uint256 => mapping(uint256 => mapping(uint256 => mapping(uint256 => bool)))))) p256State;

function cvlP256Verify(address verifier, bytes32 message, uint256 r, uint256 s, uint256 x, uint256 y) returns bool {
	return p256State[verifier][message][r][s][x][y];
}

/*
Property 14. Proxy - verify return data from the fallback is only one of the magicNumbers
Uses another contract that simulates interaction with the proxy. The reason is that the prover doesn't check all
possible calldata values so this simualtion will make the prover choose different values that will be passed on the calldata.
Rule stuck.
*/
rule proxyReturnValue {
    env e;
    address proxy;
    uint32 methodsig;
    bytes32 message;
    bytes signature;

    require proxy == SafeWebAuthnSignerProxy;
    require methodsig == sig:SafeWebAuthnSignerSingleton.isValidSignature(bytes32,bytes).selector;

    bytes4 ret = callFunction(e, proxy, methodsig, message, signature);

    assert ret == MAGIC_VALUE() || ret == to_bytes4(0);
}


