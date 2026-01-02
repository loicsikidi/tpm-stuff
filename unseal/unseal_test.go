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
	thetpm := testutil.OpenTPM(t)

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
	thetpm := testutil.OpenTPM(t)

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
