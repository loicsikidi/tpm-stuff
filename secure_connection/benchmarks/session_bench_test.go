package benchmarks_test

import (
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/loicsikidi/tpm-stuff/secure_connection/bound"
	"github.com/loicsikidi/tpm-stuff/secure_connection/common"
	"github.com/loicsikidi/tpm-stuff/secure_connection/salted"
	"github.com/loicsikidi/tpm-stuff/secure_connection/unbound"
)

// BenchmarkUnboundSession measures performance of unbound session for key creation
func BenchmarkUnboundSession(b *testing.B) {
	tpm, err := common.OpenSimulator()
	if err != nil {
		b.Fatal(err)
	}
	defer tpm.Close()

	password := []byte("testpassword")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sess, closer, err := unbound.UnboundSession(tpm, []byte(""))
		if err != nil {
			b.Fatal(err)
		}

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
		if err != nil {
			b.Fatal(err)
		}

		flush := tpm2.FlushContext{FlushHandle: rsp.ObjectHandle}
		flush.Execute(tpm)
		closer()
	}
}

// BenchmarkBoundSession measures performance of bound session for key creation
func BenchmarkBoundSession(b *testing.B) {
	tpm, err := common.OpenSimulator()
	if err != nil {
		b.Fatal(err)
	}
	defer tpm.Close()

	// Create bind entity once
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
	if err != nil {
		b.Fatal(err)
	}
	defer func() {
		flush := tpm2.FlushContext{FlushHandle: bindRsp.ObjectHandle}
		flush.Execute(tpm)
	}()

	password := []byte("testpassword")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sess, closer, err := bound.BoundSession(
			tpm,
			bindRsp.ObjectHandle,
			bindRsp.Name,
			bindPassword,
			[]byte(""),
		)
		if err != nil {
			b.Fatal(err)
		}

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
		if err != nil {
			b.Fatal(err)
		}

		flush := tpm2.FlushContext{FlushHandle: rsp.ObjectHandle}
		flush.Execute(tpm)
		closer()
	}
}

// BenchmarkSaltedSession measures performance of salted session for key creation
func BenchmarkSaltedSession(b *testing.B) {
	tpm, err := common.OpenSimulator()
	if err != nil {
		b.Fatal(err)
	}
	defer tpm.Close()

	// Create salt key once
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
	if err != nil {
		b.Fatal(err)
	}
	defer func() {
		flush := tpm2.FlushContext{FlushHandle: saltKeyRsp.ObjectHandle}
		flush.Execute(tpm)
	}()

	saltKeyPub, err := saltKeyRsp.OutPublic.Contents()
	if err != nil {
		b.Fatal(err)
	}

	password := []byte("testpassword")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encryptSess, closer, err := salted.SaltedSession(
			tpm,
			saltKeyRsp.ObjectHandle,
			*saltKeyPub,
		)
		if err != nil {
			b.Fatal(err)
		}

		createPrimary := tpm2.CreatePrimary{
			PrimaryHandle: tpm2.AuthHandle{
				Handle: tpm2.TPMRHOwner,
				Auth:   tpm2.PasswordAuth([]byte("")),
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

		rsp, err := createPrimary.Execute(tpm, encryptSess)
		if err != nil {
			b.Fatal(err)
		}

		flush := tpm2.FlushContext{FlushHandle: rsp.ObjectHandle}
		flush.Execute(tpm)
		closer()
	}
}

// BenchmarkPasswordAuth measures performance of simple password auth (baseline)
func BenchmarkPasswordAuth(b *testing.B) {
	tpm, err := common.OpenSimulator()
	if err != nil {
		b.Fatal(err)
	}
	defer tpm.Close()

	password := []byte("testpassword")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		createPrimary := tpm2.CreatePrimary{
			PrimaryHandle: tpm2.AuthHandle{
				Handle: tpm2.TPMRHOwner,
				Auth:   tpm2.PasswordAuth([]byte("")),
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
		if err != nil {
			b.Fatal(err)
		}

		flush := tpm2.FlushContext{FlushHandle: rsp.ObjectHandle}
		flush.Execute(tpm)
	}
}
