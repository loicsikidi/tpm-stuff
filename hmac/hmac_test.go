package hmac

import (
	"bytes"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/loicsikidi/go-tpm-kit/tpmcrypto"
	"github.com/loicsikidi/go-tpm-kit/tpmutil"
	"github.com/loicsikidi/tpm-stuff/internal/testutil"
)

var hmacKeyTemplate = tpm2.TPMTPublic{
	Type: tpm2.TPMAlgKeyedHash,
	ObjectAttributes: tpm2.TPMAObject{
		SignEncrypt:         true,
		FixedTPM:            true,
		FixedParent:         true,
		SensitiveDataOrigin: true,
		UserWithAuth:        true,
	},
}
var algNullTemplate = tpm2.TPMTPublic{
	Type:    tpm2.TPMAlgKeyedHash,
	NameAlg: tpm2.TPMAlgSHA256,
	ObjectAttributes: tpm2.TPMAObject{
		SignEncrypt:         true,
		FixedTPM:            true,
		FixedParent:         true,
		SensitiveDataOrigin: true,
		UserWithAuth:        true,
	},
	Parameters: tpm2.NewTPMUPublicParms(
		tpm2.TPMAlgKeyedHash,
		&tpm2.TPMSKeyedHashParms{
			Scheme: tpm2.TPMTKeyedHashScheme{
				Scheme: tpm2.TPMAlgHMAC,
				Details: tpm2.NewTPMUSchemeKeyedHash(
					tpm2.TPMAlgHMAC,
					&tpm2.TPMSSchemeHMAC{
						HashAlg: tpm2.TPMAlgNull,
					},
				),
			},
		},
	),
}

func TestHMAC(t *testing.T) {
	thetpm := testutil.OpenSimulator(t)
	tests := []struct {
		name     string
		hashAlg  tpm2.TPMIAlgHash
		wantSize int
	}{
		{
			name:     "sha256",
			hashAlg:  tpm2.TPMAlgSHA256,
			wantSize: 32,
		},
		{
			name:     "sha384",
			hashAlg:  tpm2.TPMAlgSHA384,
			wantSize: 48,
		},
		{
			name:     "sha512",
			hashAlg:  tpm2.TPMAlgSHA512,
			wantSize: 64,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			template := hmacKeyTemplate
			template.NameAlg = tt.hashAlg
			params, err := tpmcrypto.NewHMACParameters(tt.hashAlg)
			if err != nil {
				t.Fatalf("failed to create HMAC parameters: %v", err)
			}
			template.Parameters = *params
			hmacKeyHandle, err := tpmutil.CreatePrimary(thetpm, tpmutil.CreatePrimaryConfig{
				InPublic: template,
			})
			if err != nil {
				t.Fatalf("failed to create primary key: %v", err)
			}
			defer hmacKeyHandle.Close()

			data := []byte("hello world")
			cfg := tpmutil.HmacConfig{
				KeyHandle: hmacKeyHandle,
				Data:      data,
			}
			result, err := tpmutil.Hmac(thetpm, cfg)
			if err != nil {
				t.Fatalf("HMAC failed: %v", err)
			}
			if len(result) != tt.wantSize {
				t.Errorf("HMAC result size = %d, want %d", len(result), tt.wantSize)
			}

			result2, err := tpmutil.Hmac(thetpm, cfg)
			if err != nil {
				t.Fatalf("HMAC failed: %v", err)
			}
			if !bytes.Equal(result, result2) {
				t.Errorf("HMAC results do not match")
			}
		})
	}
}

func TestInvalidTemplate(t *testing.T) {
	thetpm := testutil.OpenSimulator(t)
	if _, err := tpmutil.CreatePrimary(thetpm, tpmutil.CreatePrimaryConfig{
		InPublic: algNullTemplate,
	}); err == nil {
		t.Fatalf("expected error when creating primary key with invalid template, got nil")
	}
}
