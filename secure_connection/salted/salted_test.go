package salted_test

import (
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/loicsikidi/tpm-stuff/secure_connection/common"
	"github.com/loicsikidi/tpm-stuff/secure_connection/salted"
	"github.com/stretchr/testify/require"
)

func TestSalted_KeyCreation(t *testing.T) {
	tpm, err := common.OpenSimulator()
	require.NoError(t, err)
	defer tpm.Close()

	// First, create an RSA key to use for salting (simulating an EK)
	// In production, you'd typically use the actual EK
	createSaltKey := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth([]byte("")),
		},
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgRSA,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				Decrypt:             true,
				FixedTPM:            true,
				FixedParent:         true,
				SensitiveDataOrigin: true,
				UserWithAuth:        true,
			},
			Parameters: tpm2.NewTPMUPublicParms(
				tpm2.TPMAlgRSA,
				&tpm2.TPMSRSAParms{
					KeyBits: 2048,
					Scheme: tpm2.TPMTRSAScheme{
						Scheme: tpm2.TPMAlgNull,
					},
				},
			),
		}),
	}

	saltKeyRsp, err := createSaltKey.Execute(tpm)
	require.NoError(t, err)
	defer func() {
		flush := tpm2.FlushContext{FlushHandle: saltKeyRsp.ObjectHandle}
		flush.Execute(tpm)
	}()

	// Extract the public key for the salted session
	saltKeyPub, err := saltKeyRsp.OutPublic.Contents()
	require.NoError(t, err)

	// Now create an inline salted session (recommended default)
	targetPassword := []byte("targetpassword")

	sess := salted.Salted(
		saltKeyRsp.ObjectHandle,
		*saltKeyPub,
	)

	// Create a new key with the salted session
	// The password will be encrypted using a session secret derived from
	// a salt value that was encrypted with the RSA key
	createPrimary := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth([]byte("")),
		},
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: targetPassword,
				},
			},
		},
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgECC,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				SignEncrypt:         true,
				FixedTPM:            true,
				FixedParent:         true,
				SensitiveDataOrigin: true,
				UserWithAuth:        true,
			},
			Parameters: tpm2.NewTPMUPublicParms(
				tpm2.TPMAlgECC,
				&tpm2.TPMSECCParms{
					CurveID: tpm2.TPMECCNistP256,
				},
			),
		}),
	}

	rsp, err := createPrimary.Execute(tpm, sess)
	require.NoError(t, err)
	require.NotNil(t, rsp)
	require.NotNil(t, rsp.OutPublic)

	// The password was encrypted during transmission via the salted session
	// The session secret is derived from a salt encrypted with the RSA key
	// This provides the strongest protection without requiring pre-shared secrets

	// Clean up
	flush := tpm2.FlushContext{FlushHandle: rsp.ObjectHandle}
	_, err = flush.Execute(tpm)
	require.NoError(t, err)
}

func TestSaltedSession_PersistentSession(t *testing.T) {
	tpm, err := common.OpenSimulator()
	require.NoError(t, err)
	defer tpm.Close()

	// First, create an RSA key to use for salting (simulating an EK)
	// In production, you'd typically use the actual EK
	createSaltKey := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth([]byte("")),
		},
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgRSA,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				Decrypt:             true,
				FixedTPM:            true,
				FixedParent:         true,
				SensitiveDataOrigin: true,
				UserWithAuth:        true,
			},
			Parameters: tpm2.NewTPMUPublicParms(
				tpm2.TPMAlgRSA,
				&tpm2.TPMSRSAParms{
					KeyBits: 2048,
					Scheme: tpm2.TPMTRSAScheme{
						Scheme: tpm2.TPMAlgNull,
					},
				},
			),
		}),
	}

	saltKeyRsp, err := createSaltKey.Execute(tpm)
	require.NoError(t, err)
	defer func() {
		flush := tpm2.FlushContext{FlushHandle: saltKeyRsp.ObjectHandle}
		flush.Execute(tpm)
	}()

	// Extract the public key for the salted session
	saltKeyPub, err := saltKeyRsp.OutPublic.Contents()
	require.NoError(t, err)

	// Create persistent salted session (for demonstration/performance)
	encryptSess, closer, err := salted.SaltedSession(tpm, saltKeyRsp.ObjectHandle, *saltKeyPub)
	require.NoError(t, err)
	defer closer() // Must call to release TPM slot

	targetPassword := []byte("targetpassword")

	// Use session for first operation
	createPrimary := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth([]byte("")),
		},
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: targetPassword,
				},
			},
		},
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgECC,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				SignEncrypt:         true,
				FixedTPM:            true,
				FixedParent:         true,
				SensitiveDataOrigin: true,
				UserWithAuth:        true,
			},
			Parameters: tpm2.NewTPMUPublicParms(
				tpm2.TPMAlgECC,
				&tpm2.TPMSECCParms{
					CurveID: tpm2.TPMECCNistP256,
				},
			),
		}),
	}

	rsp, err := createPrimary.Execute(tpm, encryptSess)
	require.NoError(t, err)
	require.NotNil(t, rsp)

	// Reuse same session for second operation (demonstrates session reuse)
	createPrimary2 := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth([]byte("")), // Reusing persistent session
		},
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: []byte("anotherpassword"),
				},
			},
		},
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgECC,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				SignEncrypt:         true,
				FixedTPM:            true,
				FixedParent:         true,
				SensitiveDataOrigin: true,
				UserWithAuth:        true,
			},
			Parameters: tpm2.NewTPMUPublicParms(
				tpm2.TPMAlgECC,
				&tpm2.TPMSECCParms{
					CurveID: tpm2.TPMECCNistP256,
				},
			),
		}),
	}

	rsp2, err := createPrimary2.Execute(tpm, encryptSess)
	require.NoError(t, err)
	require.NotNil(t, rsp2)

	// Clean up both keys
	flush := tpm2.FlushContext{FlushHandle: rsp.ObjectHandle}
	_, err = flush.Execute(tpm)
	require.NoError(t, err)

	flush2 := tpm2.FlushContext{FlushHandle: rsp2.ObjectHandle}
	_, err = flush2.Execute(tpm)
	require.NoError(t, err)
}
