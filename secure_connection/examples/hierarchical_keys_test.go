package examples_test

import (
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/loicsikidi/tpm-stuff/secure_connection/common"
	"github.com/loicsikidi/tpm-stuff/secure_connection/salted"
	"github.com/stretchr/testify/require"
)

// TestHierarchicalKeyCreation demonstrates creating a hierarchy of keys
// with BOTH authorization and parameter encryption.
//
// New Design (2 sessions per command):
//  1. Authorization session (HMAC with authValue) - proves you know the password
//  2. Encryption session (salted) - encrypts sensitive parameters on bus
//
// Scenario:
// 1. Create EK (salt key) for salted encryption sessions
// 2. Create primary key A under Owner hierarchy
// 3. Create key B (child of A) with password "xoxo"
//
// Each operation uses TWO sessions:
//   - AuthHandle.Auth: HMAC session with entity's authValue (authorization)
//   - Execute(...session): Salted session for parameter encryption
//
// Key Insight:
// Authorization and encryption are SEPARATE concerns handled by SEPARATE sessions.
func TestHierarchicalKeyCreation(t *testing.T) {
	tpm, err := common.OpenSimulator()
	require.NoError(t, err)
	defer tpm.Close()

	// Step 1: Create EK for salted sessions (simulating production EK)
	createEK := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHEndorsement,
			Auth:   tpm2.PasswordAuth([]byte("")),
		},
		InPublic: tpm2.New2B(tpm2.RSAEKTemplate),
	}

	ekRsp, err := createEK.Execute(tpm)
	require.NoError(t, err)
	defer func() {
		flush := tpm2.FlushContext{FlushHandle: ekRsp.ObjectHandle}
		flush.Execute(tpm)
	}()

	ekPub, err := ekRsp.OutPublic.Contents()
	require.NoError(t, err)
	t.Logf("✓ Step 1: Created EK for salted sessions")

	// Create the encryption session (reusable across all operations)
	encryptSess := salted.Salted(ekRsp.ObjectHandle, *ekPub)

	// Step 2: Create primary key A under Owner hierarchy
	keyAPassword := []byte("passwordA")

	// Authorization session for Owner hierarchy (empty password)
	authSessOwner := common.HMACAuth([]byte(""))

	createPrimaryA := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   authSessOwner, // Authorizes access to Owner
		},
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: keyAPassword, // Password FOR key A (will be encrypted)
				},
			},
		},
		InPublic: tpm2.New2B(tpm2.ECCSRKTemplate),
	}

	// Pass encryption session to Execute()
	keyARsp, err := createPrimaryA.Execute(tpm, encryptSess)
	require.NoError(t, err)
	defer func() {
		flush := tpm2.FlushContext{FlushHandle: keyARsp.ObjectHandle}
		flush.Execute(tpm)
	}()
	t.Logf("✓ Step 2: Created primary key A (Owner → A)")

	// Step 3: Create key B (child of A) with password "xoxo"
	keyBPassword := []byte("xoxo")

	// Authorization session for key A (password: "passwordA")
	authSessKeyA := common.HMACAuth(keyAPassword)

	createKeyB := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{
			Handle: keyARsp.ObjectHandle,
			Name:   keyARsp.Name,
			Auth:   authSessKeyA, // Authorizes access to key A
		},
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: keyBPassword, // Password FOR key B (will be encrypted)
				},
			},
		},
		InPublic: tpm2.New2B(tpm2.ECCSRKTemplate),
	}

	// Pass encryption session to Execute()
	keyBRsp, err := createKeyB.Execute(tpm, encryptSess)
	require.NoError(t, err)

	// Load key B (reuse authSessKeyA since we still auth to key A)
	loadKeyB := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: keyARsp.ObjectHandle,
			Name:   keyARsp.Name,
			Auth:   authSessKeyA, // Authorizes access to key A
		},
		InPrivate: keyBRsp.OutPrivate,
		InPublic:  keyBRsp.OutPublic,
	}

	// Pass encryption session to Execute()
	loadKeyBRsp, err := loadKeyB.Execute(tpm, encryptSess)
	require.NoError(t, err)
	defer func() {
		flush := tpm2.FlushContext{FlushHandle: loadKeyBRsp.ObjectHandle}
		flush.Execute(tpm)
	}()
	t.Logf("✓ Step 3: Created and loaded key B (A → B)")

	// Summary
	t.Log("\n=== Summary ===")
	t.Log("✓ All operations completed with BOTH authorization AND parameter encryption")
	t.Log("✓ Key hierarchy: EK → Owner → A → B")
	t.Log("\n=== Session Design ===")
	t.Log("Each command used TWO sessions:")
	t.Log("  1. Authorization session (HMAC with authValue) via AuthHandle.Auth")
	t.Log("     - authSessOwner: proves we know Owner password (empty)")
	t.Log("     - authSessKeyA: proves we know key A password ('passwordA')")
	t.Log("  2. Encryption session (salted) via Execute(...session)")
	t.Log("     - encryptSess: encrypts sensitive parameters (AES-128-CFB)")
	t.Log("     - REUSED across all operations (single EK-salted session)")
	t.Log("\n=== Key Insights ===")
	t.Log("✅ Authorization and encryption are SEPARATE concerns")
	t.Log("✅ Authorization sessions change per entity (match authValue)")
	t.Log("✅ Encryption session can be reused (no entity binding)")
	t.Log("✅ All passwords were encrypted on the TPM bus")
}
