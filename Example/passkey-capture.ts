/**
 * Phase 0 passkey live-capture harness.
 *
 * Links a *passkey-enabled* test WhatsApp account through vs-baileys and captures the real
 * passkey pairing traffic — the `passkey_prologue_request` (WebAuthn challenge) and
 * `crsc_continuation` nodes — so we can settle the one open design question: who produces the
 * WebAuthn assertion, and whether an in-browser ceremony is even possible (RP-ID/origin).
 *
 * Prereq: the test account must have a passkey created (WhatsApp -> Settings -> Account ->
 * Passkeys -> Create). Without an account passkey the server never sends the passkey request
 * and this just links normally (a useful baseline).
 *
 * Run:  npx tsx ./Example/passkey-capture.ts            (scan the QR)
 *       npx tsx ./Example/passkey-capture.ts --use-pairing-code
 *
 * Everything (incl. raw inbound nodes at trace level) is mirrored to passkey-capture-logs.txt.
 */
import { Boom } from '@hapi/boom'
import readline from 'readline'
import qrcode from 'qrcode-terminal'
import makeWASocket, {
	Browsers,
	DisconnectReason,
	fetchLatestBaileysVersion,
	makeCacheableSignalKeyStore,
	useMultiFileAuthState,
	WebAuthnResponse
} from '../src'
import type { BinaryNode } from '../src'
import P from 'pino'

const logger = P({
	level: 'trace',
	transport: {
		targets: [
			{ target: 'pino-pretty', options: { colorize: true }, level: 'info' },
			{ target: 'pino/file', options: { destination: './passkey-capture-logs.txt' }, level: 'trace' }
		]
	}
})

const usePairingCode = process.argv.includes('--use-pairing-code')

const rl = readline.createInterface({ input: process.stdin, output: process.stdout })
const question = (text: string) => new Promise<string>(resolve => rl.question(text, resolve))

const banner = (title: string) => {
	console.log('\n============================================================')
	console.log(`  ${title}`)
	console.log('============================================================')
}

const startSock = async () => {
	const { state, saveCreds } = await useMultiFileAuthState('passkey_capture_auth')
	const { version, isLatest } = await fetchLatestBaileysVersion()
	console.log(`Using WA version ${version.join('.')} (latest: ${isLatest})`)

	const sock = makeWASocket({
		version,
		logger,
		auth: {
			creds: state.creds,
			keys: makeCacheableSignalKeyStore(state.keys, logger)
		},
		browser: Browsers.appropriate('Chrome'),
		// nothing to reply to during capture
		getMessage: async () => undefined
	})

	// --- Belt-and-braces raw wire capture (alongside the trace-level file log) ---
	sock.ws.on('CB:notification,type:passkey_prologue_request', (node: BinaryNode) => {
		banner('RAW <notification type="passkey_prologue_request">')
		console.dir(node, { depth: null })
	})
	sock.ws.on('CB:notification,type:crsc_continuation', (node: BinaryNode) => {
		banner('RAW <notification type="crsc_continuation">')
		console.dir(node, { depth: null })
	})

	// --- Passkey events (parsed) ---
	sock.ev.on('pairing.passkey-request', async ({ publicKey }) => {
		banner('PAIRING.PASSKEY-REQUEST  (this is the primary artifact)')
		console.log(JSON.stringify(publicKey, null, 2))
		console.log('\nKey things to note: rpId, allowCredentials, userVerification, extensions.')
		console.log('Also observe what — if anything — your phone is showing right now.')

		const pasted = await question(
			'\nPaste a WebAuthn assertion JSON to forward (or press Enter to skip):\n'
		)
		if (pasted.trim()) {
			try {
				await sock.sendPasskeyResponse(JSON.parse(pasted) as WebAuthnResponse)
				console.log('Assertion forwarded — waiting for continuation...')
			} catch (err) {
				console.error('Failed to send passkey response:', err)
			}
		} else {
			console.log('Skipped. Flow will stall here (expected without an authenticator).')
		}
	})

	sock.ev.on('pairing.passkey-confirmation', async ({ code, skipHandoffUX }) => {
		banner('PAIRING.PASSKEY-CONFIRMATION')
		console.log(`Verification code: ${code}   (skipHandoffUX: ${skipHandoffUX})`)
		if (skipHandoffUX) {
			console.log('skipHandoffUX set — WHAM would auto-confirm. Confirming now...')
			await sock.sendPasskeyConfirmation()
			return
		}
		const answer = await question('Does this code match your phone? Confirm? (y/N): ')
		if (answer.trim().toLowerCase() === 'y') {
			await sock.sendPasskeyConfirmation()
			console.log('Confirmed — expecting pair-success next.')
		}
	})

	sock.ev.on('pairing.passkey-error', ({ error, continuation }) => {
		banner('PAIRING.PASSKEY-ERROR')
		console.error(`continuation=${continuation}:`, error)
	})

	sock.ev.on('connection.update', async update => {
		const { connection, lastDisconnect, qr } = update
		if (qr) {
			banner('Scan this QR with the passkey-enabled test phone')
			qrcode.generate(qr, { small: true })
			if (usePairingCode && !sock.authState.creds.registered) {
				const phoneNumber = await question('Enter phone number for pairing code (E.164, no +):\n')
				console.log(`Pairing code: ${await sock.requestPairingCode(phoneNumber)}`)
			}
		}
		if (connection === 'open') {
			banner('CONNECTION OPEN — linked successfully')
			console.log('If this happened without a passkey step, the account has no passkey (baseline).')
		}
		if (connection === 'close') {
			const statusCode = (lastDisconnect?.error as Boom)?.output?.statusCode
			if (statusCode !== DisconnectReason.loggedOut) {
				console.log('Connection closed, reconnecting...')
				startSock()
			} else {
				console.log('Logged out.')
			}
		}
	})

	sock.ev.on('creds.update', saveCreds)

	return sock
}

startSock().catch(err => {
	console.error('Harness failed to start:', err)
	process.exit(1)
})
