package primary

import (
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/loicsikidi/go-tpm-kit/tpmutil"
	"github.com/loicsikidi/tpm-stuff/internal/testutil"
)

// TestHierarchyAuth demonstrates that primary key creation is protected by hierarchy authorization.
func TestHierarchyAuth(t *testing.T) {
	thetpm := testutil.OpenTPM(t)

	authPwd := []byte("mysecret")
	hca := tpm2.HierarchyChangeAuth{
		AuthHandle: tpm2.TPMRHOwner,
		NewAuth: tpm2.TPM2BAuth{
			Buffer: authPwd,
		},
	}
	if _, err := hca.Execute(thetpm); err != nil {
		t.Errorf("failed HierarchyChangeAuth: %v", err)
	}

	if _, err := tpmutil.CreatePrimary(thetpm, tpmutil.CreatePrimaryConfig{
		InPublic: tpmutil.ECCSRKTemplate,
		Auth:     tpm2.PasswordAuth(authPwd),
	}); err != nil {
		t.Errorf("failed CreatePrimary: %v", err)
	}

	if _, err := tpmutil.CreatePrimary(thetpm, tpmutil.CreatePrimaryConfig{
		InPublic: tpmutil.ECCSRKTemplate,
		Auth:     tpm2.PasswordAuth([]byte("wrongpassword")),
	}); err == nil {
		t.Errorf("expected CreatePrimary to fail with wrong password, but it succeeded")
	}
}

// TestPrimaryKeyAuth demonstrates that primary key usage is protected by key authorization.
func TestPrimaryKeyAuth(t *testing.T) {
	thetpm := testutil.OpenTPM(t)

	authPwd := []byte("mysecret")
	srkHandle, err := tpmutil.CreatePrimary(thetpm, tpmutil.CreatePrimaryConfig{
		InPublic: tpmutil.ECCSRKTemplate,
		UserAuth: authPwd,
	})
	if err != nil {
		t.Errorf("failed CreatePrimary: %v", err)
	}

	if _, err := tpmutil.Create(thetpm, tpmutil.CreateConfig{
		ParentHandle: srkHandle,
		ParentAuth:   tpm2.PasswordAuth(authPwd),
		InPublic:     tpmutil.ECCSRKTemplate,
	}); err != nil {
		t.Errorf("failed Create: %v", err)
	}

	if _, err := tpmutil.Create(thetpm, tpmutil.CreateConfig{
		ParentHandle: srkHandle,
		ParentAuth:   tpm2.PasswordAuth([]byte("wrongpassword")),
		InPublic:     tpmutil.ECCSRKTemplate,
	}); err == nil {
		t.Errorf("expected Create to fail with wrong password, but it succeeded")
	}
}
