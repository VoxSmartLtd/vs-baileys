import { randomBytes } from 'node:crypto'
import { proto } from '../../../WAProto/index.js'
import { makePasskeyPairing } from '../../Socket/pair-passkey'
import type {
	AuthenticationState,
	BaileysEventEmitter,
	BaileysEventMap,
	WebAuthnPublicKey,
	WebAuthnResponse
} from '../../Types'
import {
	aesDecryptGCM,
	bytesToCrockford,
	Curve,
	getPlatformType,
	hkdf,
	hmacSign,
	initAuthCreds,
	sha256
} from '../../Utils'
import type { ILogger } from '../../Utils/logger'
import { getBinaryNodeChild, getBinaryNodeChildBuffer, type BinaryNode } from '../../WABinary'

const BROWSER: [string, string, string] = ['Test', 'Chrome', '1.0']
const silentLogger = { warn: () => {}, debug: () => {} } as unknown as ILogger

const sampleWebAuthnPublicKey: WebAuthnPublicKey = {
	challenge: Buffer.from('challenge-bytes').toString('base64url'),
	timeout: 60000,
	rpId: 'whatsapp.com',
	allowCredentials: [{ id: Buffer.from('cred-id').toString('base64url'), type: 'public-key' }],
	userVerification: 'required'
}

const sampleWebAuthnResponse: WebAuthnResponse = {
	id: 'credential-id',
	rawId: Buffer.from('raw-credential-id').toString('base64url'),
	type: 'public-key',
	response: {
		clientDataJSON: Buffer.from('{"type":"webauthn.get"}').toString('base64url'),
		authenticatorData: Buffer.from('auth-data').toString('base64url'),
		signature: Buffer.from('signature').toString('base64url'),
		userHandle: null
	}
}

/** collects emitted events + sent IQ nodes, and answers `iq get` queries the way the server would */
const makeHarness = () => {
	const emitted: { event: string; arg: unknown }[] = []
	const sentNodes: BinaryNode[] = []

	const ev = {
		emit: (event: string, arg: unknown) => {
			emitted.push({ event, arg })
			return true
		},
		on: () => {},
		off: () => {},
		removeAllListeners: () => {}
	} as unknown as BaileysEventEmitter

	const query = async (node: BinaryNode): Promise<BinaryNode> => {
		sentNodes.push(node)
		const child = (node.content as BinaryNode[])[0]
		if (node.attrs.type === 'get' && child?.tag === 'ref') {
			return { tag: 'iq', attrs: {}, content: [{ tag: 'ref', attrs: {}, content: Buffer.from('server-ref-123') }] }
		}

		if (node.attrs.type === 'get' && child?.tag === 'passkey_request_options') {
			return {
				tag: 'iq',
				attrs: {},
				content: [
					{ tag: 'passkey_request_options', attrs: {}, content: Buffer.from(JSON.stringify(sampleWebAuthnPublicKey)) }
				]
			}
		}

		return { tag: 'iq', attrs: { type: 'result' } }
	}

	const creds = initAuthCreds()
	const authState = { creds, keys: {} } as unknown as AuthenticationState
	const passkey = makePasskeyPairing({ authState, ev, query, browser: BROWSER, logger: silentLogger })

	const emittedOf = <T extends keyof BaileysEventMap>(event: T) =>
		emitted.filter(e => e.event === event).map(e => e.arg as BaileysEventMap[T])
	const sentOf = (childTag: string) => sentNodes.filter(n => (n.content as BinaryNode[])[0]?.tag === childTag)

	return { creds, ev, query, passkey, emittedOf, sentOf, sentNodes }
}

const notification = (childTag: string, content: Buffer): BinaryNode => ({
	tag: 'notification',
	attrs: { from: '@s.whatsapp.net', type: childTag },
	content: [{ tag: childTag, attrs: {}, content }]
})

/** simulates the primary device: derives shared secret, code and encryption key the way the phone would */
const simulatePrimary = (companionPub: Buffer, companionNonce: Buffer, deviceType: number, ref: string) => {
	const primaryKeyPair = Curve.generateKeyPair()
	const primaryNonce = randomBytes(32)
	const sharedSecret = Curve.sharedKey(primaryKeyPair.private, companionPub)

	const salt = `Companion Pairing ${deviceType} with ref ${ref}`
	const encryptionKey = Buffer.from(
		hkdf(sharedSecret, 32, { salt: Buffer.from(salt, 'utf-8'), info: 'Pairing Information Encryption Key' })
	)

	const digest = sha256(Buffer.concat([companionNonce, primaryKeyPair.public]))
	const codeBytes = Buffer.alloc(5)
	for (let i = 0; i < 5; i++) {
		codeBytes[i] = (primaryNonce[i] ?? 0) ^ (digest[i] ?? 0)
	}

	const encodedCode = bytesToCrockford(codeBytes)
	const expectedCode = `${encodedCode.slice(0, 4)}-${encodedCode.slice(4)}`

	const continuationContent = proto.PrimaryEphemeralIdentity.encode({
		publicKey: primaryKeyPair.public,
		nonce: primaryNonce
	}).finish()

	return { primaryKeyPair, primaryNonce, encryptionKey, expectedCode, continuationContent }
}

const decodePrologue = (sentPrologueNode: BinaryNode) => {
	const prologue = getBinaryNodeChild(sentPrologueNode, 'passkey_prologue')!
	const prologuePayloadBuf = getBinaryNodeChildBuffer(prologue, 'prologue_payload')!
	const prologuePayload = proto.ProloguePayload.decode(prologuePayloadBuf)
	const ident = proto.CompanionEphemeralIdentity.decode(prologuePayload.companionEphemeralIdentity!)
	return { prologue, prologuePayloadBuf, prologuePayload, ident }
}

describe('passkey pairing', () => {
	it('drives the full flow end-to-end and securely transports the rotated advSecretKey', async () => {
		const h = makeHarness()
		const oldAdvSecret = h.creds.advSecretKey

		// 1. prologue request notification -> rotates advSecretKey, emits passkey-request
		await h.passkey.handlePasskeyNotification(
			notification('passkey_request_options', Buffer.from(JSON.stringify(sampleWebAuthnPublicKey)))
		)

		expect(h.creds.advSecretKey).not.toBe(oldAdvSecret)
		expect(h.emittedOf('creds.update')[0]?.advSecretKey).toBe(h.creds.advSecretKey)
		expect(h.emittedOf('pairing.passkey-request')[0]?.publicKey.rpId).toBe('whatsapp.com')

		// 2. send the WebAuthn assertion -> sends <passkey_prologue> with a handoff proof
		await h.passkey.sendPasskeyResponse(sampleWebAuthnResponse)

		const prologueNode = h.sentOf('passkey_prologue')[0]!
		const { prologue, prologuePayloadBuf, ident } = decodePrologue(prologueNode)
		expect(getBinaryNodeChildBuffer(prologue, 'credential_id')).toEqual(Buffer.from('raw-credential-id'))
		expect(JSON.parse(getBinaryNodeChildBuffer(prologue, 'webauthn_assertion')!.toString())).toEqual(
			sampleWebAuthnResponse
		)

		// handoff proof must be present + correct (derived from the pre-rotation advSecretKey)
		const expectedHandoffKey = Buffer.from(
			hkdf(Buffer.from(oldAdvSecret, 'base64'), 32, { info: 'shortcake-passkey-handoff-v1' })
		)
		const expectedProof = hmacSign(Buffer.from(prologuePayloadBuf), expectedHandoffKey)
		expect(getBinaryNodeChildBuffer(prologue, 'pairing_handoff_proof')).toEqual(expectedProof)

		// 3. continuation notification -> derives code + encryption key
		const deviceType = getPlatformType(BROWSER[1])
		expect(ident.deviceType).toBe(deviceType)
		expect(ident.ref).toBe('server-ref-123')
		const companionPub = Buffer.from(ident.publicKey!)

		const primary = simulatePrimary(companionPub, Buffer.alloc(0), deviceType, 'server-ref-123')
		await h.passkey.handlePasskeyContinuationNotification(
			notification('primary_ephemeral_identity', Buffer.from(primary.continuationContent))
		)

		// companion_nonce is sent back; read it to compute the expected code from the primary's view
		const companionNonce = getBinaryNodeChildBuffer(h.sentOf('companion_nonce')[0]!, 'companion_nonce')!
		const digest = sha256(Buffer.concat([companionNonce, primary.primaryKeyPair.public]))
		const codeBytes = Buffer.alloc(5)
		for (let i = 0; i < 5; i++) {
			codeBytes[i] = (primary.primaryNonce[i] ?? 0) ^ (digest[i] ?? 0)
		}
		const encodedCode = bytesToCrockford(codeBytes)
		const expectedCode = `${encodedCode.slice(0, 4)}-${encodedCode.slice(4)}`

		const confirmation = h.emittedOf('pairing.passkey-confirmation')[0]!
		expect(confirmation.code).toBe(expectedCode)
		expect(confirmation.code).toMatch(/^[0-9A-Z]{4}-[0-9A-Z]{4}$/)
		expect(confirmation.skipHandoffUX).toBe(true)

		// 4. confirm -> encrypted pairing request that the primary can decrypt
		await h.passkey.sendPasskeyConfirmation()

		// derive the encryption key from the primary side using the real companionNonce/pub
		const salt = `Companion Pairing ${deviceType} with ref server-ref-123`
		const encryptionKey = Buffer.from(
			hkdf(Curve.sharedKey(primary.primaryKeyPair.private, companionPub), 32, {
				salt: Buffer.from(salt, 'utf-8'),
				info: 'Pairing Information Encryption Key'
			})
		)

		const wrappedBuf = getBinaryNodeChildBuffer(h.sentOf('encrypted_pairing_request')[0]!, 'encrypted_pairing_request')!
		const wrapped = proto.EncryptedPairingRequest.decode(wrappedBuf)
		const decrypted = aesDecryptGCM(
			Buffer.from(wrapped.encryptedPayload!),
			encryptionKey,
			Buffer.from(wrapped.iv!),
			Buffer.alloc(0)
		)
		const pairingReq = proto.PairingRequest.decode(decrypted)

		expect(Buffer.from(pairingReq.advSecret!).toString('base64')).toBe(h.creds.advSecretKey)
		expect(Buffer.from(pairingReq.companionPublicKey!)).toEqual(Buffer.from(h.creds.noiseKey.public))
		expect(Buffer.from(pairingReq.companionIdentityKey!)).toEqual(Buffer.from(h.creds.signedIdentityKey.public))
	})

	it('omits the handoff proof and sets skipHandoffUX=false when there is no valid handoff key', async () => {
		const h = makeHarness()

		// go straight to sendPasskeyResponse without a prior prologue notification -> no handoff key
		await h.passkey.sendPasskeyResponse(sampleWebAuthnResponse)
		const { prologue, ident } = decodePrologue(h.sentOf('passkey_prologue')[0]!)
		expect(getBinaryNodeChildBuffer(prologue, 'pairing_handoff_proof')).toBeUndefined()

		const deviceType = getPlatformType(BROWSER[1])
		const companionPub = Buffer.from(ident.publicKey!)
		const primary = simulatePrimary(companionPub, Buffer.alloc(0), deviceType, 'server-ref-123')
		await h.passkey.handlePasskeyContinuationNotification(
			notification('primary_ephemeral_identity', Buffer.from(primary.continuationContent))
		)

		expect(h.emittedOf('pairing.passkey-confirmation')[0]?.skipHandoffUX).toBe(false)
	})

	it('falls back to fetching options when the notification cannot be parsed', async () => {
		const h = makeHarness()
		// notification has a child of the wrong tag -> parse fails -> getPasskeyRequestOptions() succeeds
		await h.passkey.handlePasskeyNotification(notification('wrong_tag', Buffer.from('not json')))

		expect(h.sentOf('passkey_request_options').length).toBe(1)
		expect(h.emittedOf('pairing.passkey-request')[0]?.publicKey.rpId).toBe('whatsapp.com')
	})

	it('emits a passkey-error (continuation=true) when continuation arrives without a linking cache', async () => {
		const h = makeHarness()
		const content = proto.PrimaryEphemeralIdentity.encode({
			publicKey: randomBytes(32),
			nonce: randomBytes(32)
		}).finish()
		await h.passkey.handlePasskeyContinuationNotification(
			notification('primary_ephemeral_identity', Buffer.from(content))
		)

		const err = h.emittedOf('pairing.passkey-error')[0]
		expect(err?.continuation).toBe(true)
		expect(err?.error.message).toMatch(/without a linking cache/)
	})

	it('rejects sendPasskeyConfirmation before an encryption key has been derived', async () => {
		const h = makeHarness()
		await h.passkey.sendPasskeyResponse(sampleWebAuthnResponse)
		// no continuation yet -> no encryption key
		await expect(h.passkey.sendPasskeyConfirmation()).rejects.toThrow(/encryption key/)
	})
})
