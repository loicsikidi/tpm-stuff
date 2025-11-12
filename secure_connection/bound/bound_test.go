package bound_test

import (
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/loicsikidi/tpm-stuff/secure_connection/bound"
	"github.com/loicsikidi/tpm-stuff/secure_connection/common"
	"github.com/stretchr/testify/require"
)

func TestBound_KeyCreation(t *testing.T) {
	tpm, err := common.OpenSimulator()
	require.NoError(t, err)
	defer tpm.Close()

	// First, create a bind entity (a primary key to bind our session to)
	bindPassword := []byte("bindpassword")

	createBindEntity := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth([]byte("")),
		},
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: bindPassword,
				},
			},
		},
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgECC,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				Decrypt:             true,
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

	bindRsp, err := createBindEntity.Execute(tpm)
	require.NoError(t, err)
	defer func() {
		flush := tpm2.FlushContext{FlushHandle: bindRsp.ObjectHandle}
		flush.Execute(tpm)
	}()

	// Now create an inline bound session (recommended default)
	targetPassword := []byte("targetpassword")

	sess := bound.Bound(
		bindRsp.ObjectHandle,
		bindRsp.Name,
		bindPassword,
		[]byte(""), // Owner auth for creating the new key
	)

	// Create a new key with the bound session
	// The password will be encrypted using a session secret derived from both
	// the owner auth and the bind entity's auth
	createPrimary := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   sess,
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

	rsp, err := createPrimary.Execute(tpm)
	require.NoError(t, err)
	require.NotNil(t, rsp)
	require.NotNil(t, rsp.OutPublic)

	// The password was encrypted during transmission via the bound session
	// The session secret is derived from both the bind entity's auth and the owner auth
	// This provides stronger protection than an unbound session

	// Clean up
	flush := tpm2.FlushContext{FlushHandle: rsp.ObjectHandle}
	_, err = flush.Execute(tpm)
	require.NoError(t, err)
}

func TestBoundSession_PersistentSession(t *testing.T) {
	tpm, err := common.OpenSimulator()
	require.NoError(t, err)
	defer tpm.Close()

	// First, create a bind entity (a primary key to bind our session to)
	bindPassword := []byte("bindpassword")

	createBindEntity := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth([]byte("")),
		},
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: bindPassword,
				},
			},
		},
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgECC,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				Decrypt:             true,
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

	bindRsp, err := createBindEntity.Execute(tpm)
	require.NoError(t, err)
	defer func() {
		flush := tpm2.FlushContext{FlushHandle: bindRsp.ObjectHandle}
		flush.Execute(tpm)
	}()

	// Create persistent bound session (for demonstration/performance)
	sess, closer, err := bound.BoundSession(tpm, bindRsp.ObjectHandle, bindRsp.Name, bindPassword, []byte(""))
	require.NoError(t, err)
	defer closer() // Must call to release TPM slot

	targetPassword := []byte("targetpassword")

	// Use session for first operation
	createPrimary := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   sess,
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

	rsp, err := createPrimary.Execute(tpm)
	require.NoError(t, err)
	require.NotNil(t, rsp)

	// Reuse same session for second operation (demonstrates session reuse)
	createPrimary2 := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   sess, // Reusing persistent session
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

	rsp2, err := createPrimary2.Execute(tpm)
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
