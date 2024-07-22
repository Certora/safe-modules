using SafeWebAuthnSharedSigner as SafeWebAuthnSharedSigner;

definition MAGIC_VALUE() returns bytes4 = to_bytes4(0x1626ba7e);
definition LEGACY_MAGIC_VALUE() returns bytes4 = to_bytes4(0x20c13b0b);

// sanity rule
// passed - https://prover.certora.com/output/80942/9b5618ab52b8479fb7ee19a89a14b86e?anonymousKey=d1d8512effeb9393c7b89d249e3c188f26406cc3
use builtin rule sanity filtered { f -> f.contract == currentContract }

// getConfiguration() will return zeroes if the caller is not Safe account
/*rule verifyGetConfigurationReturnsZerosForNonSafeAccount()
{
    env e; address account;
    // uint256 x; uint256 y; P256.Verifiers verifiers;
    SafeWebAuthnSharedSigner.Signer signerGet;

    // (x, y, verifiers) = getConfiguration(e,account);
    signerGet = getConfiguration(e,account);

    // We need somehow to verify that a calling contract is Safe account
    // but how??
    bool isSafeAccount;

    // assert !isSafeAccount => x == 0 && y == 0 && verifiers == 0;
    assert !isSafeAccount => signerGet.x == 0 && signerGet.y == 0 && signerGet.verifiers == 0;
    satisfy true;
}*/


// getConfiguration() will return correct configuration if the caller is Safe account
/*rule verifyGetConfigurationReturnsCorrectConfiguration()
{
    env e; address account;

    uint256 x_source; uint256 y_source; P256.Verifiers verifiers_source;
    // We need to have a getter for the above that show the real values of the Safe account
    // x_source = 
    // y_source =
    // verifiers_source = 

    uint256 x; uint256 y; P256.Verifiers verifiers;
    (x, y, verifiers) = getConfiguration(e,account);

    // We need somehow to verify that a calling contract is Safe account
    // but how??
    bool isSafeAccount;

    assert isSafeAccount => x == 0 && y == 0 && verifiers == 0;
    satisfy true;
}*/


// configure() must be called with delegatecall otherwise reverts (verify the modifier)
// passed - https://prover.certora.com/output/80942/b4b1f970a40c42b584137b5f01c25a0e?anonymousKey=ee3e1bc4c40e77f63c7aafbf94abf7accaaee42a
rule verifyModifierOnlyDelegateCall()
{
    env e;
    SafeWebAuthnSharedSigner.Signer signer;

    configure@withrevert(e,signer);
    bool configureReverted = lastReverted;

    assert _SELF(e) == SafeWebAuthnSharedSigner => configureReverted;
    // assert e.msg.sender == SafeWebAuthnSharedSigner => configureReverted;
    // assert e.msg.sender != SafeWebAuthnSharedSigner => !configureReverted;
}


// configure() integrity: sets correctly the applied settings - verify by checking
// the output of getConfiguration()
// failed - https://prover.certora.com/output/80942/4e4e56f3544e4a11b6c346dd8d679ea6?anonymousKey=2a2fda141ffdd61965e46ea01b9af4d159259691
rule verifyConfigureIntegrity()
{
    env e;
    SafeWebAuthnSharedSigner.Signer signerSet;
    SafeWebAuthnSharedSigner.Signer signerGet;
    address account;

    configure(e,signerSet);
    signerGet = getConfiguration(e,account);

    assert e.msg.sender == account => signerSet == signerGet;
}


// configure() can be called multiple times and the last setting is the one that is set
// failed - https://prover.certora.com/output/80942/7198c36038b344a5bc79c0a50ea0c545?anonymousKey=e3110b0b69e17291ba8af3a2717d50176a4292a0
rule verifyConfigureMultipleTimes()
{
    env e;
    SafeWebAuthnSharedSigner.Signer signerSet1;
    SafeWebAuthnSharedSigner.Signer signerSet2;
    SafeWebAuthnSharedSigner.Signer signerGet;
    address account;

    configure(e,signerSet1);
    configure(e,signerSet2);
    signerGet = getConfiguration(e,account);

    assert e.msg.sender == account => signerSet2 == signerGet;
}


// configure() won't revert if called twice with valid input
// passed - https://prover.certora.com/output/80942/3e779bea01f243849b88dce4c076b8d0?anonymousKey=70ff154349c0ee14b6772dbed18b8e3458b1a6b3
rule verifyConfigureWontRevert()
{
    env e;
    SafeWebAuthnSharedSigner.Signer signerSet1;
    SafeWebAuthnSharedSigner.Signer signerSet2;

    configure(e,signerSet1);
    configure@withrevert(e,signerSet2);
    bool configureReverted = lastReverted;

    assert signerSet1 == signerSet2 => !configureReverted;
}


// isValidSignature(bytes memory data, bytes calldata signature) behaves similarly to 
// isValidSignature(bytes32 message, bytes calldata signature) i.e.,
// both fail or pass at the same time when bytes32 message == keccak256(data)
// failed - https://prover.certora.com/output/80942/a4f3dd01294a436b849794db7952d278?anonymousKey=88f64a73a75c3e5617beb2c7f6e6914f6a4ae4c4
rule isValidSignatureCoherence()
{
    env e;
    bytes data; bytes32 message; bytes signature;

    // bytes4 LEGACY_MAGIC_VALUE = 0x20c13b0b;
    // bytes4 MAGIC_VALUE = 0x1626ba7e;

    bytes4 magicValueLegacy = isValidSignature(e,data,signature);
    bytes4 magicValue = isValidSignature(e,message,signature);

    assert message == keccak256(data) =>
            (magicValueLegacy == LEGACY_MAGIC_VALUE() && magicValue == MAGIC_VALUE()) ||
            (magicValueLegacy != LEGACY_MAGIC_VALUE() && magicValue != MAGIC_VALUE());
}


// failed - https://prover.certora.com/output/80942/c9292aa42ad14020968418c32744a49a?anonymousKey=4180c35e299966155ba7fec2f533b3c113831073
rule isValidSignatureCoherenceExtended()
{
    env e; method f; calldataarg args;

    bytes data; bytes32 message; bytes signature;

    // bytes4 LEGACY_MAGIC_VALUE = 0x20c13b0b;
    // bytes4 MAGIC_VALUE = 0x1626ba7e;

    bytes4 magicValueLegacy = isValidSignature@withrevert(e,data,signature);
    bool firstRevert = lastReverted;

    f(e, args); // allow to call any method

    bytes4 magicValue = isValidSignature@withrevert(e,message,signature);
    bool secondRevert = lastReverted;


    assert message == keccak256(data) => firstRevert == secondRevert;

    // assert message == keccak256(data) =>
    //         (magicValueLegacy == LEGACY_MAGIC_VALUE() && magicValue == MAGIC_VALUE()) ||
    //         (magicValueLegacy != LEGACY_MAGIC_VALUE() && magicValue != MAGIC_VALUE());

    assert (!firstRevert && !secondRevert) =>
            magicValueLegacy == LEGACY_MAGIC_VALUE() <=> magicValue == MAGIC_VALUE();
}
