package salted

import (
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// Salted creates an inline salted HMAC session for parameter encryption only.
// A salted session uses an asymmetric key (typically EK or SRK) to encrypt a salt value.
// The session secret is derived from this salt, providing strong protection without
// requiring a pre-shared secret.
//
// This session provides ONLY parameter encryption, NOT authorization.
// Combine with an authorization session (e.g., HMAC with authValue) for complete protection.
//
// This is the recommended default approach due to its simplicity:
//   - No explicit lifecycle management (automatic cleanup)
//   - Can be reused across multiple Execute() calls
//   - No risk of TPM session slot exhaustion
//
// Session parameters:
//   - Session type: HMAC (inline/ephemeral)
//   - tpmKey: Asymmetric key (e.g., EK) for encrypting salt
//   - bind: TPM_RH_NULL (no bind entity)
//   - Encryption: AES-128-CFB parameter encryption
//   - Authorization: None (pure encryption session)
//
// This provides the strongest protection but has higher performance overhead due to
// asymmetric cryptography (~67% slower than unbound/bound sessions).
// Ideal for initial device provisioning or when no pre-shared secrets exist.
//
// Example usage:
//
//	// Create EK first
//	ekRsp, _ := tpm2.CreatePrimary{
//	    PrimaryHandle: tpm2.TPMRHEndorsement,
//	    InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
//	}.Execute(tpm)
//	ekPub, _ := ekRsp.OutPublic.Contents()
//
//	// Create salted encryption session
//	encryptSess := salted.Salted(ekRsp.ObjectHandle, *ekPub)
//
//	// Create HMAC auth session
//	authSess := common.HMACAuth(ownerAuth)
//
//	// Use both sessions for encrypted + authorized command
//	rsp, err := tpm2.CreatePrimary{
//	    PrimaryHandle: tpm2.AuthHandle{
//	        Handle: tpm2.TPMRHOwner,
//	        Auth:   tpm2.MultiSession(authSess, encryptSess),
//	    },
//	    InSensitive: tpm2.TPM2BSensitiveCreate{
//	        Sensitive: &tpm2.TPMSSensitiveCreate{
//	            UserAuth: tpm2.TPM2BAuth{Buffer: password},
//	        },
//	    },
//	    // ...
//	}.Execute(tpm)
func Salted(
	saltKeyHandle tpm2.TPMHandle,
	saltKeyPublic tpm2.TPMTPublic,
) tpm2.Session {
	return tpm2.HMAC(
		tpm2.TPMAlgSHA256,
		16, // nonceCaller size
		tpm2.Salted(saltKeyHandle, saltKeyPublic),
		tpm2.AESEncryption(128, tpm2.EncryptInOut),
	)
}

// SaltedSession creates a persistent salted HMAC session for parameter encryption only.
// This variant provides explicit lifecycle control and better performance
// for multiple successive operations (amortizes StartAuthSession + RSA cost).
//
// This session provides ONLY parameter encryption, NOT authorization.
// Combine with an authorization session (e.g., HMAC with authValue) for complete protection.
//
// Use this when:
//   - Performance is critical (many operations)
//   - Explicit session lifecycle control is needed
//   - You want to reuse the same TPM session handle
//
// The caller MUST call the returned closer function to release the TPM session slot.
//
// Session parameters:
//   - Session type: HMAC (persistent with TPM handle)
//   - TPM Handle: 0x03000000-0x03000003 (limited slots)
//   - tpmKey: Asymmetric key (e.g., EK) for encrypting salt
//   - bind: TPM_RH_NULL (no bind entity)
//   - Encryption: AES-128-CFB parameter encryption
//   - Authorization: None (pure encryption session)
//
// Example usage:
//
//	encryptSess, closer, err := salted.SaltedSession(tpm, ekHandle, ekPublic)
//	if err != nil {
//	    return err
//	}
//	defer closer() // CRITICAL: must call to release TPM slot
//
//	authSess := common.HMACAuth(ownerAuth)
//
//	// Use both sessions for multiple operations
//	rsp1, err := cmd1.Execute(tpm)
//	rsp2, err := cmd2.Execute(tpm)
func SaltedSession(
	tpm transport.TPM,
	saltKeyHandle tpm2.TPMHandle,
	saltKeyPublic tpm2.TPMTPublic,
) (tpm2.Session, func() error, error) {
	return tpm2.HMACSession(
		tpm,
		tpm2.TPMAlgSHA256,
		16, // nonceCaller size
		tpm2.Salted(saltKeyHandle, saltKeyPublic),
		tpm2.AESEncryption(128, tpm2.EncryptInOut),
	)
}
