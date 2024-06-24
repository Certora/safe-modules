using SafeWebAuthnSignerProxy as proxy;
using SafeWebAuthnSignerSingleton as singleton;

methods{
    function createSigner(uint256, uint256, P256.Verifiers) external returns (address);
    function hasNoCode(address) external returns (bool) envfree;
    function getAccountCodeLength(address account) external returns (uint256) envfree;
    function SafeWebAuthnSignerFactory._hasNoCode(address a) internal returns (bool) => hasNoCodeSummary(a);
    function getSigner(uint256 x, uint256 y, P256.Verifiers v) internal returns (address) => getSignerGhost(x, y, v);
    
}

// Summary is correct only if the unique signer rule is proved spec GetSigner
ghost getSignerGhost(uint256, uint256, P256.Verifiers) returns address {
    axiom forall uint256 x1. forall uint256 y1. forall P256.Verifiers v1.
    forall uint256 x2. forall uint256 y2. forall P256.Verifiers v2.
    (getSignerGhost(x1, y1, v1) == getSignerGhost(x2, y2, v2)) <=> (x1 == x2 && y1 == y2 && v1 == v2); 
}

function hasNoCodeSummary(address a) returns bool
{
    return getAccountCodeLength(a) > 0;
}

definition MAGIC_VALUE() returns bytes4 = to_bytes4(0x1626ba7e);

/*
┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ Singleton implementation never change (Proved)                                                                      │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
*/
rule singletonNeverChanges()
{
    env e;
    method f;
    calldataarg args;
    address currentSingleton = currentContract.SINGLETON;

    f(e, args);

    assert currentSingleton == currentContract.SINGLETON;
}

/*
┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ createSigner and getSigner always returns the same address   (Proved under assumption)                              │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
*/

rule createAndGetSignerEquivalence(){
    env e;

    uint256 createX;
    uint256 createY;
    P256.Verifiers createVerifier;

    address signer1 = createSigner(e, createX, createY, createVerifier);

    uint256 getX;
    uint256 getY;
    P256.Verifiers getVerifier;
    
    address signer2 = getSigner(e, getX, getY, getVerifier);
    
    assert signer1 == signer2 <=> (createX == getX && createY == getY && createVerifier == getVerifier);
}

/*
┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ Has no code integrity  (Proved)                                                                                     │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
*/
rule hasNoCodeIntegrity()
{
    address a;
    assert (a == proxy) => !hasNoCode(a);
}

/*
┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ isValidSignatureForSigner Consistency (Proved)                                                                        │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
*/

rule isValidSignatureForSignerConsistency()
{
    env e;
    env e1;
    env e2;
    require e1.msg.value == 0 && e2.msg.value == 0;
    
    method f;
    calldataarg args;

    uint x;
    uint y;
    P256.Verifiers verifier;
    
    bytes signature;
    bytes32 message;

    bytes4 magic1 = isValidSignatureForSigner@withrevert(e1, message, signature, x, y, verifier);
    bool firstRevert = lastReverted;

    f(e, args);

    bytes4 magic2 = isValidSignatureForSigner@withrevert(e2, message, signature, x, y, verifier);
    bool secondRevert = lastReverted;

    assert firstRevert == secondRevert;
    assert (!firstRevert && !secondRevert) => (magic1 == MAGIC_VALUE()) <=> (magic2 == MAGIC_VALUE());
}

rule getSignerRevertingConditions {
    env e;
    uint256 x;
    uint256 y;
    P256.Verifiers verifiers;

    bool triedTransferringEth = e.msg.value != 0;

    getSigner@withrevert(e, x, y, verifiers);

    assert lastReverted <=> triedTransferringEth;
}

/*
┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ Correctness of Signer Creation. (Proved)                                                                            │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
*/

ghost mathint numOfCreation;
ghost mapping(address => uint) address_map;
ghost address signerAddress;

hook EXTCODESIZE(address addr) uint v{
    require address_map[addr] == v;
}

hook CREATE2(uint value, uint offset, uint length, bytes32 salt) address v{
    require(v == signerAddress);
    numOfCreation = numOfCreation + 1;
    address_map[v] = length;
}

rule SignerCreationCantOverride()
{
    env e;
    require numOfCreation == 0;

    uint x;
    uint y;
    P256.Verifiers verifier;

    address a = getSigner(e, x, y, verifier);
    require address_map[a] == 0;

    createSigner(e, x, y, verifier);
    createSigner@withrevert(e, x, y, verifier);

    assert numOfCreation < 2;
}