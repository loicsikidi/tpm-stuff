package unbound_test

import (
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/loicsikidi/tpm-stuff/secure_connection/common"
	"github.com/loicsikidi/tpm-stuff/secure_connection/unbound"
	"github.com/stretchr/testify/require"
)

func TestUnbound_KeyCreation(t *testing.T) {
	tpm, err := common.OpenSimulator()
	require.NoError(t, err)
	defer tpm.Close()

	// Create a primary key with password protection using encrypted session
	password := []byte("mysecretpassword")

	// Create inline unbound session (recommended default)
	sess := unbound.Unbound([]byte("")) // Owner auth empty for simulator

	createPrimary := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   sess,
		},
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: password,
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

	// The password was encrypted during transmission via the unbound session
	// This protects the password from passive eavesdropping on the bus

	// Clean up
	flush := tpm2.FlushContext{FlushHandle: rsp.ObjectHandle}
	_, err = flush.Execute(tpm)
	require.NoError(t, err)
}

func TestUnboundSession_PersistentSession(t *testing.T) {
	tpm, err := common.OpenSimulator()
	require.NoError(t, err)
	defer tpm.Close()

	// Create persistent unbound session (for demonstration/performance)
	sess, closer, err := unbound.UnboundSession(tpm, []byte(""))
	require.NoError(t, err)
	defer closer() // Must call to release TPM slot

	password := []byte("mysecretpassword")

	// Use session for first operation
	createPrimary := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   sess,
		},
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: password,
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
