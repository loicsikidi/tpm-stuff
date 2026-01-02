package unseal

import (
	"bytes"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/loicsikidi/go-tpm-kit/tpmutil"
	"github.com/loicsikidi/tpm-stuff/internal/testutil"
)

var sealTemplate = tpm2.TPMTPublic{
	Type:    tpm2.TPMAlgKeyedHash,
	NameAlg: tpm2.TPMAlgSHA256,
	ObjectAttributes: tpm2.TPMAObject{
		FixedTPM:     true,
		FixedParent:  true,
		UserWithAuth: true,
		NoDA:         true,
	},
}

// TestUnsealCreatePrimary tests the unsealing of data using a primary key.
func TestUnsealCreatePrimary(t *testing.T) {
	thetpm := testutil.OpenSimulator(t)

	dataToSeal := []byte("secret")

	t.Run("without password", func(t *testing.T) {
		sealHandle, err := tpmutil.CreatePrimary(thetpm, tpmutil.CreatePrimaryConfig{
			SealingData: dataToSeal,
			InPublic:    sealTemplate,
		})
		if err != nil {
			t.Fatalf("could not create primary key: %v", err)
		}
		defer sealHandle.Close()

		unsealRsp, err := tpm2.Unseal{
			ItemHandle: tpmutil.ToAuthHandle(sealHandle),
		}.Execute(thetpm)
		if err != nil {
			t.Fatalf("could not unseal data: %v", err)
		}

		if !bytes.Equal(dataToSeal, unsealRsp.OutData.Buffer) {
			t.Fatalf("unsealed data does not match got %s, expected %s", unsealRsp.OutData.Buffer, dataToSeal)
		}
	})

	t.Run("with password", func(t *testing.T) {
		password := []byte("mypassword")
		sealHandle, err := tpmutil.CreatePrimary(thetpm, tpmutil.CreatePrimaryConfig{
			SealingData: dataToSeal,
			InPublic:    sealTemplate,
			UserAuth:    password,
		})
		if err != nil {
			t.Fatalf("could not create primary key: %v", err)
		}
		defer sealHandle.Close()

		unsealRsp, err := tpm2.Unseal{
			ItemHandle: tpmutil.ToAuthHandle(sealHandle, tpm2.PasswordAuth(password)),
		}.Execute(thetpm)
		if err != nil {
			t.Fatalf("could not unseal data: %v", err)
		}

		if !bytes.Equal(dataToSeal, unsealRsp.OutData.Buffer) {
			t.Fatalf("unsealed data does not match got %s, expected %s", unsealRsp.OutData.Buffer, dataToSeal)
		}
	})
}

func TestUnsealCreate(t *testing.T) {
	thetpm := testutil.OpenSimulator(t)

	dataToSeal := []byte("secret")
	skrHandle, err := tpmutil.CreatePrimary(thetpm, tpmutil.CreatePrimaryConfig{
		InPublic: tpmutil.ECCSRKTemplate,
	})
	if err != nil {
		t.Fatalf("could not create primary key: %v", err)
	}
	defer skrHandle.Close()

	t.Run("without password", func(t *testing.T) {
		keyHandle, err := tpmutil.Create(thetpm, tpmutil.CreateConfig{
			ParentHandle: skrHandle,
			InPublic:     sealTemplate,
			SealingData:  dataToSeal,
		})
		if err != nil {
			t.Fatalf("could not create key: %v", err)
		}
		defer keyHandle.Close()

		unsealRsp, err := tpm2.Unseal{
			ItemHandle: tpmutil.ToAuthHandle(keyHandle),
		}.Execute(thetpm)
		if err != nil {
			t.Fatalf("could not unseal data: %v", err)
		}

		if !bytes.Equal(dataToSeal, unsealRsp.OutData.Buffer) {
			t.Fatalf("unsealed data does not match got %s, expected %s", unsealRsp.OutData.Buffer, dataToSeal)
		}
	})

	t.Run("with password", func(t *testing.T) {
		password := []byte("mypassword")
		keyHandle, err := tpmutil.Create(thetpm, tpmutil.CreateConfig{
			ParentHandle: skrHandle,
			InPublic:     sealTemplate,
			SealingData:  dataToSeal,
			UserAuth:     password,
		})
		if err != nil {
			t.Fatalf("could not create key: %v", err)
		}
		defer keyHandle.Close()

		unsealRsp, err := tpm2.Unseal{
			ItemHandle: tpmutil.ToAuthHandle(keyHandle, tpm2.PasswordAuth(password)),
		}.Execute(thetpm)
		if err != nil {
			t.Fatalf("could not unseal data: %v", err)
		}

		if !bytes.Equal(dataToSeal, unsealRsp.OutData.Buffer) {
			t.Fatalf("unsealed data does not match got %s, expected %s", unsealRsp.OutData.Buffer, dataToSeal)
		}
	})
}

// TestSealDataSizeLimits tests the size limits for sealed data based on NameAlg.
// The maximum size for sealed data is limited by MAX_SYM_DATA (128 bytes) in TPM 2.0,
// which is consistent across all hash algorithms (SHA1, SHA256, SHA384, SHA512).
func TestSealDataSizeLimits(t *testing.T) {
	thetpm := testutil.OpenSimulator(t)

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
		{tpm2.TPMAlgSHA512, 128, "SHA512 allows up to 128 bytes"},
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
			keyHandle.Close()

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
