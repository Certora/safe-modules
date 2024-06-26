// 11155111 = Sepolia testnet chain id
const APP_CHAIN_ID = 11155111

// Sep testnet shortname
// https://eips.ethereum.org/EIPS/eip-3770
const APP_CHAIN_SHORTNAME = 'sep'

/*
  Some of the contracts used in the PoC app are still experimental, and not included in
  the production deployment packages, thus we need to hardcode their addresses here.
  Deployment commit: https://github.com/safe-global/safe-modules/commit/3853f34f31837e0a0aee47a4452564278f8c62ba
*/
const SAFE_WEBAUTHN_SHARED_SIGNER_ADDRESS = '0x608Cf2e3412c6BDA14E6D8A0a7D27c4240FeD6F1'

const SAFE_MULTISEND_ADDRESS = '0x38869bf66a61cF6bDB996A6aE40D5853Fd43B526'

const SAFE_4337_MODULE_ADDRESS = '0x75cf11467937ce3F2f357CE24ffc3DBF8fD5c226'

const SAFE_MODULE_SETUP_ADDRESS = '0x2dd68b007B46fBe91B9A7c3EDa5A7a1063cB5b47'

const P256_VERIFIER_ADDRESS = '0xcA89CBa4813D5B40AeC6E57A30d0Eeb500d6531b' // FCLP256Verifier

const SAFE_PROXY_FACTORY_ADDRESS = '0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67'

const SAFE_SINGLETON_ADDRESS = '0x29fcB43b46531BcA003ddC8FCB67FFE91900C762'

const ENTRYPOINT_ADDRESS = '0x0000000071727De22E5E9d8BAf0edAc6f37da032'

const XANDER_BLAZE_NFT_ADDRESS = '0xBb9ebb7b8Ee75CDBf64e5cE124731A89c2BC4A07'

export {
  SAFE_MODULE_SETUP_ADDRESS,
  APP_CHAIN_ID,
  ENTRYPOINT_ADDRESS,
  SAFE_MULTISEND_ADDRESS,
  SAFE_WEBAUTHN_SHARED_SIGNER_ADDRESS,
  SAFE_4337_MODULE_ADDRESS,
  SAFE_PROXY_FACTORY_ADDRESS,
  SAFE_SINGLETON_ADDRESS,
  XANDER_BLAZE_NFT_ADDRESS,
  P256_VERIFIER_ADDRESS,
  APP_CHAIN_SHORTNAME,
}
