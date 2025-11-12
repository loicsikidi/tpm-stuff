package bound

import (
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// Bound creates an inline bound HMAC session for parameter encryption.
// A bound session uses TPM_RH_NULL for tpmKey but binds to a specific entity.
// The session secret is derived from both the authValue of the authorized entity
// and the bind entity's authValue, providing stronger protection.
//
// This is the recommended default approach due to its simplicity:
//   - No explicit lifecycle management (automatic cleanup)
//   - Can be reused across multiple Execute() calls
//   - No risk of TPM session slot exhaustion
//
// Session parameters:
//   - Session type: HMAC (inline/ephemeral)
//   - tpmKey: TPM_RH_NULL (no asymmetric key)
//   - bind: Specified entity (enhances session secret)
//   - Encryption: AES-128-CFB parameter encryption
//
// Best practice: The bind entity should ideally be different from the authorized
// entity for maximum security.
//
// Example usage:
//
//	// Create bind entity first
//	bindRsp, _ := tpm2.CreatePrimary{...}.Execute(tpm)
//
//	// Create bound session
//	sess := bound.Bound(bindRsp.ObjectHandle, bindRsp.Name, bindAuth, ownerAuth)
//
//	// Use for encrypted command
//	rsp, err := tpm2.CreatePrimary{
//	    PrimaryHandle: tpm2.AuthHandle{
//	        Handle: tpm2.TPMRHOwner,
//	        Auth:   sess,
//	    },
//	    InSensitive: tpm2.TPM2BSensitiveCreate{
//	        Sensitive: &tpm2.TPMSSensitiveCreate{
//	            UserAuth: tpm2.TPM2BAuth{Buffer: password},
//	        },
//	    },
//	    // ...
//	}.Execute(tpm)
func Bound(
	bindHandle tpm2.TPMHandle,
	bindName tpm2.TPM2BName,
	bindAuth []byte,
	authValue []byte,
) tpm2.Session {
	return tpm2.HMAC(
		tpm2.TPMAlgSHA256,
		16, // nonceCaller size
		tpm2.Bound(bindHandle, bindName, bindAuth),
		tpm2.Auth(authValue),
		tpm2.AESEncryption(128, tpm2.EncryptInOut),
	)
}

// BoundSession creates a persistent bound HMAC session with a TPM handle.
// This variant provides explicit lifecycle control and better performance
// for multiple successive operations (amortizes StartAuthSession cost).
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
//   - tpmKey: TPM_RH_NULL (no asymmetric key)
//   - bind: Specified entity (enhances session secret)
//   - Encryption: AES-128-CFB parameter encryption
//
// Example usage:
//
//	sess, closer, err := bound.BoundSession(tpm, bindHandle, bindName, bindAuth, ownerAuth)
//	if err != nil {
//	    return err
//	}
//	defer closer() // CRITICAL: must call to release TPM slot
//
//	// Use session for multiple operations
//	rsp1, err := cmd1.Execute(tpm)
//	rsp2, err := cmd2.Execute(tpm)
func BoundSession(
	tpm transport.TPM,
	bindHandle tpm2.TPMHandle,
	bindName tpm2.TPM2BName,
	bindAuth []byte,
	authValue []byte,
) (tpm2.Session, func() error, error) {
	return tpm2.HMACSession(
		tpm,
		tpm2.TPMAlgSHA256,
		16, // nonceCaller size
		tpm2.Bound(bindHandle, bindName, bindAuth),
		tpm2.Auth(authValue),
		tpm2.AESEncryption(128, tpm2.EncryptInOut),
	)
}
