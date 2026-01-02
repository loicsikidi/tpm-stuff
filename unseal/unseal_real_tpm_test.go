//go:build linux && localtest

package unseal

import (
	"bytes"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
	"github.com/loicsikidi/go-tpm-kit/tpmutil"
)

// TestSealDataSizeLimitsRealTPM tests the size limits for sealed data on a real TPM.
// The maximum size for sealed data is limited by MAX_SYM_DATA (128 bytes) in TPM 2.0,
// which is consistent across all hash algorithms (SHA1, SHA256, SHA384, SHA512).
func TestSealDataSizeLimitsRealTPM(t *testing.T) {
	thetpm, err := linuxtpm.Open("/dev/tpmrm0")
	if err != nil {
		t.Fatalf("could not open TPM: %v", err)
	}
	defer thetpm.Close()

	skrHandle, err := tpmutil.CreatePrimary(thetpm, tpmutil.CreatePrimaryConfig{
		InPublic: tpmutil.ECCSRKTemplate,
	})
	if err != nil {
		t.Fatalf("could not create primary key: %v", err)
	}
	defer skrHandle.Close()

	tests := []struct {
		nameAlg     tpm2.TPMAlgID
		maxSize     int
		description string
	}{
		{tpm2.TPMAlgSHA1, 128, "SHA1 allows up to 128 bytes"},
		{tpm2.TPMAlgSHA256, 128, "SHA256 allows up to 128 bytes"},
		{tpm2.TPMAlgSHA384, 128, "SHA384 allows up to 128 bytes"},
	}

	for _, tc := range tests {
		t.Run(tc.description, func(t *testing.T) {
			template := tpm2.TPMTPublic{
				Type:    tpm2.TPMAlgKeyedHash,
				NameAlg: tc.nameAlg,
				ObjectAttributes: tpm2.TPMAObject{
					FixedTPM:     true,
					FixedParent:  true,
					UserWithAuth: true,
					NoDA:         true,
				},
			}

			// Test with data at maximum size - should succeed
			dataAtMax := make([]byte, tc.maxSize)
			for i := range dataAtMax {
				dataAtMax[i] = byte(i % 256)
			}

			keyHandle, err := tpmutil.Create(thetpm, tpmutil.CreateConfig{
				ParentHandle: skrHandle,
				InPublic:     template,
				SealingData:  dataAtMax,
			})
			if err != nil {
				t.Fatalf("failed to seal data at max size (%d bytes) with %v: %v", tc.maxSize, tc.nameAlg, err)
			}

			unsealRsp, err := tpm2.Unseal{
				ItemHandle: tpmutil.ToAuthHandle(keyHandle),
			}.Execute(thetpm)
			if err != nil {
				t.Fatalf("failed to unseal data at max size: %v", err)
			}

			if !bytes.Equal(dataAtMax, unsealRsp.OutData.Buffer) {
				t.Fatalf("unsealed data does not match for max size")
			}

			if err := keyHandle.Close(); err != nil {
				t.Errorf("could not close key handle: %v", err)
			}

			// Test with data exceeding maximum size - should fail
			dataOverMax := make([]byte, tc.maxSize+1)
			for i := range dataOverMax {
				dataOverMax[i] = byte(i % 256)
			}

			keyHandle, err = tpmutil.Create(thetpm, tpmutil.CreateConfig{
				ParentHandle: skrHandle,
				InPublic:     template,
				SealingData:  dataOverMax,
			})
			if err == nil {
				keyHandle.Close()
				t.Fatalf("expected error when sealing data over max size (%d bytes) with %v, but succeeded", tc.maxSize+1, tc.nameAlg)
			}
		})
	}
}
