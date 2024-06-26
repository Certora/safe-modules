import { expect } from 'chai'
import { deployments, ethers } from 'hardhat'
import { buildSignatureBytes, logGas } from '@safe-global/safe-4337/src/utils/execution'
import {
  buildSafeUserOpTransaction,
  buildPackedUserOperationFromSafeUserOperation,
  calculateSafeOperationHash,
  packGasParameters,
} from '@safe-global/safe-4337/src/utils/userOp'
import { chainId, encodeMultiSendTransactions } from '@safe-global/safe-4337/test/utils/encoding'
import { WebAuthnCredentials } from '../../utils/webauthnShim'
import { decodePublicKey, encodeWebAuthnSignature } from '../../../src/utils/webauthn'

describe('Safe4337Module', () => {
  const setupTests = deployments.createFixture(async ({ deployments }) => {
    const {
      SafeModuleSetup,
      SafeL2,
      SafeProxyFactory,
      MultiSend,
      FCLP256Verifier,
      Safe4337Module,
      SafeSignerLaunchpad,
      EntryPoint,
      SafeWebAuthnSignerFactory,
      SafeWebAuthnSharedSigner,
    } = await deployments.fixture()

    const [user] = await ethers.getSigners()
    const entryPoint = await ethers.getContractAt('IEntryPoint', EntryPoint.address)
    const module = await ethers.getContractAt(Safe4337Module.abi, Safe4337Module.address)
    const proxyFactory = await ethers.getContractAt(SafeProxyFactory.abi, SafeProxyFactory.address)
    const multiSend = await ethers.getContractAt('MultiSend', MultiSend.address)
    const safeModuleSetup = await ethers.getContractAt(SafeModuleSetup.abi, SafeModuleSetup.address)
    const signerLaunchpad = await ethers.getContractAt('SafeSignerLaunchpad', SafeSignerLaunchpad.address)
    const singleton = await ethers.getContractAt(SafeL2.abi, SafeL2.address)
    const signerFactory = await ethers.getContractAt('SafeWebAuthnSignerFactory', SafeWebAuthnSignerFactory.address)
    const sharedSigner = await ethers.getContractAt('SafeWebAuthnSharedSigner', SafeWebAuthnSharedSigner.address)
    const verifiers = BigInt(FCLP256Verifier.address)

    const navigator = {
      credentials: new WebAuthnCredentials(),
    }

    return {
      user,
      proxyFactory,
      multiSend,
      safeModuleSetup,
      module,
      entryPoint,
      signerLaunchpad,
      singleton,
      signerFactory,
      sharedSigner,
      verifiers,
      navigator,
    }
  })

  describe('SafeSignerLaunchpad', () => {
    describe('executeUserOp - new account', () => {
      it('should execute user operation', async () => {
        const { user, proxyFactory, safeModuleSetup, module, entryPoint, signerLaunchpad, singleton, signerFactory, navigator, verifiers } =
          await setupTests()

        const credential = navigator.credentials.create({
          publicKey: {
            rp: {
              name: 'Safe',
              id: 'safe.global',
            },
            user: {
              id: ethers.getBytes(ethers.id('chucknorris')),
              name: 'chucknorris',
              displayName: 'Chuck Norris',
            },
            challenge: ethers.toBeArray(Date.now()),
            pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
          },
        })
        const publicKey = decodePublicKey(credential.response)
        const signerAddress = await signerFactory.getSigner(publicKey.x, publicKey.y, verifiers)

        const launchpadInitializer = signerLaunchpad.interface.encodeFunctionData('setup', [
          singleton.target,
          signerFactory.target,
          publicKey.x,
          publicKey.y,
          verifiers,
          safeModuleSetup.target,
          safeModuleSetup.interface.encodeFunctionData('enableModules', [[module.target]]),
          module.target,
        ])
        const safeSalt = Date.now()
        const safe = await proxyFactory.createProxyWithNonce.staticCall(signerLaunchpad.target, launchpadInitializer, safeSalt)
        const userOp = {
          sender: safe,
          nonce: ethers.toBeHex(await entryPoint.getNonce(safe, 0)),
          initCode: ethers.solidityPacked(
            ['address', 'bytes'],
            [
              proxyFactory.target,
              proxyFactory.interface.encodeFunctionData('createProxyWithNonce', [signerLaunchpad.target, launchpadInitializer, safeSalt]),
            ],
          ),
          callData: signerLaunchpad.interface.encodeFunctionData('promoteAccountAndExecuteUserOp', [
            signerFactory.target,
            publicKey.x,
            publicKey.y,
            verifiers,
            user.address,
            ethers.parseEther('0.5'),
            '0x',
            0,
          ]),
          preVerificationGas: ethers.toBeHex(60000),
          ...packGasParameters({
            verificationGasLimit: 1000000,
            callGasLimit: 2500000,
            maxPriorityFeePerGas: 10000000000,
            maxFeePerGas: 10000000000,
          }),
          paymasterAndData: '0x',
        }

        const safeInitOp = {
          userOpHash: await entryPoint.getUserOpHash({ ...userOp, signature: '0x' }),
          validAfter: 0,
          validUntil: 0,
          entryPoint: entryPoint.target,
        }
        const safeInitOpHash = ethers.TypedDataEncoder.hash(
          { verifyingContract: await signerLaunchpad.getAddress(), chainId: await chainId() },
          {
            SafeInitOp: [
              { type: 'bytes32', name: 'userOpHash' },
              { type: 'uint48', name: 'validAfter' },
              { type: 'uint48', name: 'validUntil' },
              { type: 'address', name: 'entryPoint' },
            ],
          },
          safeInitOp,
        )

        const assertion = navigator.credentials.get({
          publicKey: {
            challenge: ethers.getBytes(safeInitOpHash),
            rpId: 'safe.global',
            allowCredentials: [{ type: 'public-key', id: new Uint8Array(credential.rawId) }],
            userVerification: 'required',
          },
        })
        const signature = ethers.solidityPacked(
          ['uint48', 'uint48', 'bytes'],
          [safeInitOp.validAfter, safeInitOp.validUntil, encodeWebAuthnSignature(assertion.response)],
        )

        await user.sendTransaction({ to: safe, value: ethers.parseEther('1') }).then((tx) => tx.wait())
        expect(await ethers.provider.getBalance(safe)).to.equal(ethers.parseEther('1'))
        expect(await ethers.provider.getCode(safe)).to.equal('0x')
        expect(await ethers.provider.getCode(signerAddress)).to.equal('0x')

        await logGas('WebAuthn signer Safe deployment', entryPoint.handleOps([{ ...userOp, signature }], user.address))

        expect(await ethers.provider.getBalance(safe)).to.be.lessThanOrEqual(ethers.parseEther('0.5'))
        expect(await ethers.provider.getCode(safe)).to.not.equal('0x')
        expect(await ethers.provider.getCode(signerAddress)).to.not.equal('0x')

        const [implementation] = ethers.AbiCoder.defaultAbiCoder().decode(['address'], await ethers.provider.getStorage(safe, 0))
        expect(implementation).to.equal(singleton.target)

        const safeInstance = singleton.attach(safe) as typeof singleton
        expect(await safeInstance.getOwners()).to.deep.equal([signerAddress])
      })
    })
  })

  describe('SafeWebAuthnSharedSigner', () => {
    describe('executeUserOp - new account', () => {
      it('should execute user operation', async () => {
        const { user, proxyFactory, multiSend, safeModuleSetup, module, entryPoint, singleton, sharedSigner, navigator, verifiers } =
          await setupTests()

        const credential = navigator.credentials.create({
          publicKey: {
            rp: {
              name: 'Safe',
              id: 'safe.global',
            },
            user: {
              id: ethers.getBytes(ethers.id('chucknorris')),
              name: 'chucknorris',
              displayName: 'Chuck Norris',
            },
            challenge: ethers.toBeArray(Date.now()),
            pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
          },
        })
        const publicKey = decodePublicKey(credential.response)

        const initializer = singleton.interface.encodeFunctionData('setup', [
          [sharedSigner.target],
          1,
          multiSend.target,
          multiSend.interface.encodeFunctionData('multiSend', [
            encodeMultiSendTransactions([
              {
                op: 1 as const,
                to: safeModuleSetup.target,
                data: safeModuleSetup.interface.encodeFunctionData('enableModules', [[module.target]]),
              },
              {
                op: 1 as const,
                to: sharedSigner.target,
                data: sharedSigner.interface.encodeFunctionData('configure', [{ ...publicKey, verifiers }]),
              },
            ]),
          ]),
          module.target,
          ethers.ZeroAddress,
          0,
          ethers.ZeroAddress,
        ])
        const safeSalt = Date.now()
        const safe = await proxyFactory.createProxyWithNonce.staticCall(singleton.target, initializer, safeSalt)

        const safeOp = buildSafeUserOpTransaction(
          safe,
          user.address,
          ethers.parseEther('0.5'),
          '0x',
          await entryPoint.getNonce(safe, 0),
          await entryPoint.getAddress(),
          false,
          false,
          {
            initCode: ethers.solidityPacked(
              ['address', 'bytes'],
              [
                proxyFactory.target,
                proxyFactory.interface.encodeFunctionData('createProxyWithNonce', [singleton.target, initializer, safeSalt]),
              ],
            ),
            verificationGasLimit: 700000,
          },
        )
        const safeOpHash = await module.getOperationHash(
          buildPackedUserOperationFromSafeUserOperation({
            safeOp,
            signature: '0x',
          }),
        )

        const assertion = navigator.credentials.get({
          publicKey: {
            challenge: ethers.getBytes(safeOpHash),
            rpId: 'safe.global',
            allowCredentials: [{ type: 'public-key', id: new Uint8Array(credential.rawId) }],
            userVerification: 'required',
          },
        })
        const signature = buildSignatureBytes([
          {
            signer: sharedSigner.target as string,
            data: encodeWebAuthnSignature(assertion.response),
            dynamic: true,
          },
        ])

        await user.sendTransaction({ to: safe, value: ethers.parseEther('1') }).then((tx) => tx.wait())
        expect(await ethers.provider.getBalance(safe)).to.equal(ethers.parseEther('1'))
        expect(await ethers.provider.getCode(safe)).to.equal('0x')
        expect(await sharedSigner.getConfiguration(safe)).to.deep.equal([0n, 0n, 0n])

        await logGas(
          'WebAuthn signer Safe deployment',
          entryPoint.handleOps([buildPackedUserOperationFromSafeUserOperation({ safeOp, signature })], user.address),
        )

        expect(await ethers.provider.getBalance(safe)).to.be.lessThanOrEqual(ethers.parseEther('0.5'))
        expect(await ethers.provider.getCode(safe)).to.not.equal('0x')
        expect(await sharedSigner.getConfiguration(safe)).to.deep.equal([publicKey.x, publicKey.y, verifiers])

        const [implementation] = ethers.AbiCoder.defaultAbiCoder().decode(['address'], await ethers.provider.getStorage(safe, 0))
        expect(implementation).to.equal(singleton.target)

        const safeInstance = singleton.attach(safe) as typeof singleton
        expect(await safeInstance.getOwners()).to.deep.equal([sharedSigner.target])
      })
    })

    describe('executeUserOp - existing account', () => {
      it('should execute user operation', async () => {
        const { user, proxyFactory, multiSend, safeModuleSetup, module, entryPoint, singleton, sharedSigner, navigator, verifiers } =
          await setupTests()
        const credential = navigator.credentials.create({
          publicKey: {
            rp: {
              name: 'Safe',
              id: 'safe.global',
            },
            user: {
              id: ethers.getBytes(ethers.id('chucknorris')),
              name: 'chucknorris',
              displayName: 'Chuck Norris',
            },
            challenge: ethers.toBeArray(Date.now()),
            pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
          },
        })
        const publicKey = decodePublicKey(credential.response)

        const initializer = singleton.interface.encodeFunctionData('setup', [
          [sharedSigner.target],
          1,
          multiSend.target,
          multiSend.interface.encodeFunctionData('multiSend', [
            encodeMultiSendTransactions([
              {
                op: 1 as const,
                to: safeModuleSetup.target,
                data: safeModuleSetup.interface.encodeFunctionData('enableModules', [[module.target]]),
              },
              {
                op: 1 as const,
                to: sharedSigner.target,
                data: sharedSigner.interface.encodeFunctionData('configure', [{ ...publicKey, verifiers }]),
              },
            ]),
          ]),
          module.target,
          ethers.ZeroAddress,
          0,
          ethers.ZeroAddress,
        ])
        const safeSalt = Date.now()
        const safe = await proxyFactory.createProxyWithNonce.staticCall(singleton, initializer, safeSalt)
        await proxyFactory.createProxyWithNonce(singleton, initializer, safeSalt)

        const safeOp = buildSafeUserOpTransaction(
          safe,
          user.address,
          ethers.parseEther('0.5'),
          '0x',
          await entryPoint.getNonce(safe, 0),
          await entryPoint.getAddress(),
        )
        const safeOpHash = calculateSafeOperationHash(await module.getAddress(), safeOp, await chainId())
        const assertion = navigator.credentials.get({
          publicKey: {
            challenge: ethers.getBytes(safeOpHash),
            rpId: 'safe.global',
            allowCredentials: [{ type: 'public-key', id: new Uint8Array(credential.rawId) }],
            userVerification: 'required',
          },
        })
        const signature = buildSignatureBytes([
          {
            signer: sharedSigner.target as string,
            data: encodeWebAuthnSignature(assertion.response),
            dynamic: true,
          },
        ])

        await user.sendTransaction({ to: safe, value: ethers.parseEther('1') }).then((tx) => tx.wait())
        expect(await ethers.provider.getBalance(safe)).to.equal(ethers.parseEther('1'))

        const userOp = buildPackedUserOperationFromSafeUserOperation({ safeOp, signature })
        await logGas('WebAuthn signer Safe operation', entryPoint.handleOps([userOp], user.address))

        expect(await ethers.provider.getBalance(safe)).to.be.lessThanOrEqual(ethers.parseEther('0.5'))
      })
    })
  })
})
