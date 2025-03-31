package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/simulator"
	"github.com/stretchr/testify/require"
)

func TestQuote(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer thetpm.Close()

	Auth := []byte("password")

	public := tpm2.New2B(tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			SignEncrypt:         true,
			Restricted:          true,
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Scheme: tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgRSASSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgRSASSA,
						&tpm2.TPMSSigSchemeRSASSA{
							HashAlg: tpm2.TPMAlgSHA256,
						},
					),
				},
				KeyBits: 2048,
			},
		),
	},
	)

	pcrSelection := tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{
			{
				Hash:      tpm2.TPMAlgSHA256,
				PCRSelect: tpm2.PCClientCompatible.PCRs(7),
			},
		},
	}

	createPrimarySigner := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: Auth,
				},
			},
		},
		InPublic:    public,
	}
	rspSigner, err := createPrimarySigner.Execute(thetpm)
	if err != nil {
		t.Fatalf("Failed to create primary: %v", err)
	}
	flushContextSigner := tpm2.FlushContext{FlushHandle: rspSigner.ObjectHandle}
	defer flushContextSigner.Execute(thetpm)

	createPrimarySubject := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: Auth,
				},
			},
		},
		InPublic:    public,
	}
	unique := tpm2.NewTPMUPublicID(
		tpm2.TPMAlgRSA,
		&tpm2.TPM2BPublicKeyRSA{
			Buffer: []byte("subject key"),
		},
	)
	inPub, err := createPrimarySubject.InPublic.Contents()
	if err != nil {
		t.Fatalf("%v", err)
	}
	inPub.Unique = unique

	rspSubject, err := createPrimarySubject.Execute(thetpm)
	if err != nil {
		t.Fatalf("Failed to create primary: %v", err)
	}
	flushContextSubject := tpm2.FlushContext{FlushHandle: rspSubject.ObjectHandle}
	defer flushContextSubject.Execute(thetpm)

	originalBuffer := []byte("test nonce")

	quote := tpm2.Quote{
		SignHandle: tpm2.AuthHandle{
			Handle: rspSigner.ObjectHandle,
			Name:   rspSigner.Name,
			Auth:   tpm2.PasswordAuth(Auth),
		},
		QualifyingData: tpm2.TPM2BData{
			Buffer: originalBuffer,
		},
		InScheme: tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgNull,
		},
		PCRSelect: pcrSelection,
	}

	rspQuote, err := quote.Execute(thetpm)
	if err != nil {
		t.Fatalf("Failed to quote: %v", err)
	}

	quoted, err := rspQuote.Quoted.Contents()
	if err != nil {
		t.Fatalf("%v", err)
	}
	q := tpm2.Marshal(quoted)

	attestHash := sha256.Sum256(q)
	pub, err := rspSigner.OutPublic.Contents()
	if err != nil {
		t.Fatalf("%v", err)
	}
	rsaDetail, err := pub.Parameters.RSADetail()
	if err != nil {
		t.Fatalf("%v", err)
	}
	rsaUnique, err := pub.Unique.RSA()
	if err != nil {
		t.Fatalf("%v", err)
	}
	rsaPub, err := tpm2.RSAPub(rsaDetail, rsaUnique)
	if err != nil {
		t.Fatalf("%v", err)
	}

	rsassa, err := rspQuote.Signature.Signature.RSASSA()
	if err != nil {
		t.Fatalf("%v", err)
	}
	if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, attestHash[:], rsassa.Sig.Buffer); err != nil {
		t.Errorf("Signature verification failed: %v", err)
	}	
	if !cmp.Equal(originalBuffer, quoted.ExtraData.Buffer) {
		t.Errorf("Attested buffer is different from original buffer")
	}

	// Check TPMS_QUOTE_INFO
	// See definition in Part 2: Structures, section 10.12.4.
	quotePayload, err := quoted.Attested.Quote()
	if err != nil {
		t.Fatalf("%v", err)
	}
	require.NotEmpty(t, len(quotePayload.PCRDigest.Buffer), "PCR digest shouldn't be empty")
	require.Equal(t, len(pcrSelection.PCRSelections), len(quotePayload.PCRSelect.PCRSelections))
}