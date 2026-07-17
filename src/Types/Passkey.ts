/**
 * WebAuthn types used by the passkey pairing flow.
 *
 * Port of whatsmeow's `types/passkey.go`. WhatsApp sends the server-side
 * `PublicKeyCredentialRequestOptions` as JSON inside the `<passkey_request_options>`
 * node, and expects the authenticator's assertion (`PublicKeyCredential`) back as JSON
 * inside `<webauthn_assertion>`.
 *
 * Baileys does not implement the authenticator itself — like whatsmeow, it surfaces the
 * challenge to the host application and forwards the host-produced assertion verbatim.
 *
 * All binary fields are represented as **base64url (unpadded)** strings, matching both
 * the on-the-wire JSON encoding (whatsmeow's `jsonbytes.UnpaddedURLBytes`) and the shape a
 * browser `navigator.credentials.get()` result is naturally serialised into for transport.
 */

/** Server-provided WebAuthn assertion options (`PublicKeyCredentialRequestOptions`). */
export type WebAuthnPublicKey = {
	/** base64url-encoded challenge bytes */
	challenge: string
	timeout?: number
	/** relying party id (WhatsApp's domain) */
	rpId: string
	allowCredentials?: AllowedCredential[]
	userVerification?: string
	extensions?: { [key: string]: unknown }
}

export type AllowedCredential = {
	/** base64url-encoded credential id */
	id: string
	type: string
	transports?: string[]
}

/** Authenticator assertion (`PublicKeyCredential`) produced by the host. */
export type WebAuthnResponse = {
	id: string
	/** base64url-encoded raw credential id */
	rawId: string
	type: string
	response: WebAuthnResponseData
}

export type WebAuthnResponseData = {
	/** base64url-encoded clientDataJSON */
	clientDataJSON: string
	/** base64url-encoded authenticatorData */
	authenticatorData: string
	/** base64url-encoded signature */
	signature: string
	/** base64url-encoded user handle, or null when absent */
	userHandle?: string | null
}
