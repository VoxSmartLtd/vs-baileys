import { randomBytes } from 'node:crypto'
import { proto } from '../../WAProto/index.js'
import type {
	AuthenticationState,
	BaileysEventEmitter,
	WABrowserDescription,
	WebAuthnPublicKey,
	WebAuthnResponse
} from '../Types'
import { aesEncryptGCM, bytesToCrockford, Curve, getPlatformType, hkdf, hmacSign, sha256 } from '../Utils'
import type { ILogger } from '../Utils/logger'
import type { BinaryNode } from '../WABinary'
import { getBinaryNodeChildBuffer, getBinaryNodeChildString, S_WHATSAPP_NET } from '../WABinary'

/** how long a handoff proof key stays usable — matches whatsmeow (5 minutes) */
const HANDOFF_KEY_VALIDITY_MS = 5 * 60 * 1000

/** derived once from the previous advSecretKey, lets a re-pair skip the code-confirmation UX */
const HANDOFF_HKDF_INFO = 'shortcake-passkey-handoff-v1'
/** HKDF info for the ECDH-derived pairing-request encryption key */
const PAIRING_ENC_HKDF_INFO = 'Pairing Information Encryption Key'

type PasskeyLinkingCache = {
	keyPair: ReturnType<typeof Curve.generateKeyPair>
	companionNonce: Buffer
	pairingRef: string
	deviceType: proto.DeviceProps.PlatformType
	encryptionKey?: Buffer
}

type PasskeyHandoffKey = {
	hmac: Buffer
	ts: number
}

export type PasskeyPairingDeps = {
	authState: AuthenticationState
	ev: BaileysEventEmitter
	query: (node: BinaryNode, timeoutMs?: number) => Promise<BinaryNode>
	browser: WABrowserDescription
	logger: ILogger
}

export type PasskeyPairing = ReturnType<typeof makePasskeyPairing>

/**
 * Implements WhatsApp passkey (WebAuthn) companion pairing.
 *
 * Direct port of whatsmeow's `pair-passkey.go`. Baileys does not act as the WebAuthn
 * authenticator itself — the host must obtain an assertion (via `pairing.passkey-request`)
 * and hand it back through `sendPasskeyResponse`. This module owns the node/IQ choreography
 * plus the X25519 + HKDF + AES-GCM channel that securely transports the pairing request
 * (noise pubkey, identity pubkey and advSecretKey) to the primary device.
 */
export const makePasskeyPairing = ({ authState, ev, query, browser, logger }: PasskeyPairingDeps) => {
	const { creds } = authState

	let linkingCache: PasskeyLinkingCache | undefined
	let handoffKey: PasskeyHandoffKey | undefined
	let skipHandoffUX = false

	const isFromServer = (node: BinaryNode) => {
		const from = node.attrs.from
		return !from || from === S_WHATSAPP_NET || from === 's.whatsapp.net'
	}

	/** `iq get` for a server-assigned companion reference id */
	const getCompanionRef = async (): Promise<string> => {
		const resp = await query({
			tag: 'iq',
			attrs: { to: S_WHATSAPP_NET, type: 'get', xmlns: 'md' },
			content: [{ tag: 'ref', attrs: {} }]
		})
		const ref = getBinaryNodeChildString(resp, 'ref')
		if (!ref) {
			throw new Error('missing <ref> in companion ref response')
		}

		return ref
	}

	/** fallback `iq get` for the WebAuthn options if the notification could not be parsed */
	const getPasskeyRequestOptions = async (): Promise<WebAuthnPublicKey> => {
		const resp = await query({
			tag: 'iq',
			attrs: { to: S_WHATSAPP_NET, type: 'get', xmlns: 'md' },
			content: [{ tag: 'passkey_request_options', attrs: {} }]
		})
		return parsePasskeyRequestOptions(resp)
	}

	const parsePasskeyRequestOptions = (node: BinaryNode): WebAuthnPublicKey => {
		const content = getBinaryNodeChildBuffer(node, 'passkey_request_options')
		if (!content) {
			throw new Error('missing <passkey_request_options> node')
		}

		return JSON.parse(content.toString('utf-8')) as WebAuthnPublicKey
	}

	const parsePrimaryEphemeralIdentity = (node: BinaryNode): { publicKey: Buffer; nonce: Buffer } => {
		const content = getBinaryNodeChildBuffer(node, 'primary_ephemeral_identity')
		if (!content) {
			throw new Error('missing <primary_ephemeral_identity> node')
		}

		const identity = proto.PrimaryEphemeralIdentity.decode(content)
		if (identity.publicKey?.length !== 32) {
			throw new Error(`unexpected public key length ${identity.publicKey?.length} in primary ephemeral identity`)
		}

		if (identity.nonce?.length !== 32) {
			throw new Error(`unexpected nonce length ${identity.nonce?.length} in primary ephemeral identity`)
		}

		return { publicKey: Buffer.from(identity.publicKey), nonce: Buffer.from(identity.nonce) }
	}

	/**
	 * Handles a `<notification type="passkey_prologue_request">`: parses the WebAuthn challenge,
	 * stashes a handoff proof key derived from the current advSecretKey, rotates advSecretKey, and
	 * dispatches `pairing.passkey-request` for the host to answer via `sendPasskeyResponse`.
	 */
	const handlePasskeyNotification = async (node: BinaryNode) => {
		if (!isFromServer(node)) {
			logger.warn({ from: node.attrs.from }, 'ignoring passkey notification from non-server JID')
			return
		}

		let publicKey: WebAuthnPublicKey
		try {
			publicKey = parsePasskeyRequestOptions(node)
		} catch (err) {
			logger.warn({ err }, 'failed to parse passkey notification, fetching options')
			try {
				publicKey = await getPasskeyRequestOptions()
			} catch (secondErr) {
				ev.emit('pairing.passkey-error', {
					error: new Error(
						`failed to parse passkey notification (${err}); fetching options also failed (${secondErr})`
					),
					continuation: false
				})
				return
			}
		}

		// derive the handoff proof key from the CURRENT advSecretKey before rotating it
		handoffKey = {
			hmac: Buffer.from(hkdf(Buffer.from(creds.advSecretKey, 'base64'), 32, { info: HANDOFF_HKDF_INFO })),
			ts: Date.now()
		}
		// rotate the advSecretKey — the fresh value is what gets shipped in the encrypted PairingRequest
		creds.advSecretKey = randomBytes(32).toString('base64')
		ev.emit('creds.update', { advSecretKey: creds.advSecretKey })

		ev.emit('pairing.passkey-request', { publicKey })
	}

	/**
	 * Sends the host-produced WebAuthn assertion back to the server, along with a freshly
	 * generated companion ephemeral identity and (when a valid handoff key exists) a handoff proof.
	 */
	const sendPasskeyResponse = async (passkeyResp: WebAuthnResponse) => {
		const marshaledResp = Buffer.from(JSON.stringify(passkeyResp), 'utf-8')
		const companionRef = await getCompanionRef()

		const companionEphemeralKeyPair = Curve.generateKeyPair()
		const companionNonce = randomBytes(32)
		const deviceType = getPlatformType(browser[1])

		const ident = proto.CompanionEphemeralIdentity.encode({
			publicKey: companionEphemeralKeyPair.public,
			deviceType,
			ref: companionRef
		}).finish()
		const commitment = sha256(Buffer.concat([ident, companionNonce]))
		const prologuePayload = proto.ProloguePayload.encode({
			companionEphemeralIdentity: ident,
			commitment: { hash: commitment }
		}).finish()

		linkingCache = {
			keyPair: companionEphemeralKeyPair,
			companionNonce,
			pairingRef: companionRef,
			deviceType
		}

		const prologueContent: BinaryNode[] = [
			{ tag: 'credential_id', attrs: {}, content: Buffer.from(passkeyResp.rawId, 'base64url') },
			{ tag: 'webauthn_assertion', attrs: {}, content: marshaledResp },
			{ tag: 'prologue_payload', attrs: {}, content: Buffer.from(prologuePayload) }
		]

		const currentHandoffKey = handoffKey
		if (currentHandoffKey && Date.now() - currentHandoffKey.ts < HANDOFF_KEY_VALIDITY_MS) {
			const pairingHandoffProof = hmacSign(Buffer.from(prologuePayload), currentHandoffKey.hmac)
			prologueContent.push({ tag: 'pairing_handoff_proof', attrs: {}, content: pairingHandoffProof })
			skipHandoffUX = true
		} else {
			skipHandoffUX = false
		}

		await query({
			tag: 'iq',
			attrs: { to: S_WHATSAPP_NET, type: 'set', xmlns: 'md' },
			content: [{ tag: 'passkey_prologue', attrs: {}, content: prologueContent }]
		})

		handoffKey = undefined
	}

	/**
	 * Handles a `<notification type="crsc_continuation">`: performs the ECDH with the primary
	 * device's ephemeral key, derives the encryption key + verification code, and dispatches
	 * `pairing.passkey-confirmation` for the user to confirm.
	 */
	const handlePasskeyContinuationNotification = async (node: BinaryNode) => {
		if (!isFromServer(node)) {
			logger.warn({ from: node.attrs.from }, 'ignoring passkey continuation notification from non-server JID')
			return
		}

		try {
			const cache = linkingCache
			if (!cache) {
				throw new Error('received passkey continuation notification without a linking cache')
			}

			const { publicKey: primaryPublicKey, nonce: primaryNonce } = parsePrimaryEphemeralIdentity(node)
			const sharedSecret = Curve.sharedKey(cache.keyPair.private, primaryPublicKey)

			await query({
				tag: 'iq',
				attrs: { to: S_WHATSAPP_NET, type: 'set', xmlns: 'md' },
				content: [{ tag: 'companion_nonce', attrs: {}, content: cache.companionNonce }]
			})

			const salt = `Companion Pairing ${cache.deviceType} with ref ${cache.pairingRef}`
			cache.encryptionKey = Buffer.from(
				hkdf(sharedSecret, 32, { salt: Buffer.from(salt, 'utf-8'), info: PAIRING_ENC_HKDF_INFO })
			)

			const digest = sha256(Buffer.concat([cache.companionNonce, primaryPublicKey]))
			const codeBytes = Buffer.alloc(5)
			for (let i = 0; i < codeBytes.length; i++) {
				codeBytes[i] = (primaryNonce[i] ?? 0) ^ (digest[i] ?? 0)
			}

			const encodedCode = bytesToCrockford(codeBytes)
			ev.emit('pairing.passkey-confirmation', {
				code: `${encodedCode.slice(0, 4)}-${encodedCode.slice(4)}`,
				skipHandoffUX
			})
		} catch (error) {
			logger.warn({ error }, 'failed to handle passkey continuation notification')
			ev.emit('pairing.passkey-error', { error: error as Error, continuation: true })
		}
	}

	/**
	 * Finalises pairing: encrypts the PairingRequest (noise pubkey, identity pubkey, advSecretKey)
	 * with the ECDH-derived key and sends it. Called after the user confirms the verification code
	 * (or automatically when `skipHandoffUX` is set). The normal pair-success flow then completes.
	 */
	const sendPasskeyConfirmation = async () => {
		const cache = linkingCache
		if (!cache) {
			throw new Error('no passkey linking cache available')
		}

		if (!cache.encryptionKey) {
			throw new Error('passkey linking cache does not have an encryption key yet')
		}

		const req = proto.PairingRequest.encode({
			companionPublicKey: creds.noiseKey.public,
			companionIdentityKey: creds.signedIdentityKey.public,
			advSecret: Buffer.from(creds.advSecretKey, 'base64')
		}).finish()

		const iv = randomBytes(12)
		const encryptedReq = aesEncryptGCM(req, cache.encryptionKey, iv, Buffer.alloc(0))
		const wrappedReq = proto.EncryptedPairingRequest.encode({ encryptedPayload: encryptedReq, iv }).finish()

		await query({
			tag: 'iq',
			attrs: { to: S_WHATSAPP_NET, type: 'set', xmlns: 'md' },
			content: [{ tag: 'encrypted_pairing_request', attrs: {}, content: Buffer.from(wrappedReq) }]
		})

		linkingCache = undefined
	}

	return {
		handlePasskeyNotification,
		handlePasskeyContinuationNotification,
		sendPasskeyResponse,
		sendPasskeyConfirmation
	}
}
