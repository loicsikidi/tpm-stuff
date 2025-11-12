package common

import (
	"crypto/rand"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// GenerateRandomData generates random bytes of the specified size.
func GenerateRandomData(size int) ([]byte, error) {
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		return nil, fmt.Errorf("failed to generate random data: %w", err)
	}
	return data, nil
}

// NVIndexInfo contains information about a created NV index.
type NVIndexInfo struct {
	Handle tpm2.TPMHandle
	Name   tpm2.TPM2BName
}

// CreateNVIndex creates a test NV index with the specified attributes.
// Returns NV index information including handle and name.
func CreateNVIndex(tpm transport.TPM, index uint32, size uint16, password string) (*NVIndexInfo, error) {
	nvHandle := tpm2.TPMHandle(index)

	publicInfo := tpm2.New2B(tpm2.TPMSNVPublic{
		NVIndex: nvHandle,
		NameAlg: tpm2.TPMAlgSHA256,
		Attributes: tpm2.TPMANV{
			OwnerWrite: true,
			OwnerRead:  true,
			AuthWrite:  true,
			AuthRead:   true,
		},
		AuthPolicy: tpm2.TPM2BDigest{},
		DataSize:   size,
	})

	defineSpace := tpm2.NVDefineSpace{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth([]byte("")),
		},
		Auth: tpm2.TPM2BAuth{
			Buffer: []byte(password),
		},
		PublicInfo: publicInfo,
	}

	_, err := defineSpace.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("failed to define NV space: %w", err)
	}

	// Read the public info to get the name
	readPub := tpm2.NVReadPublic{
		NVIndex: nvHandle,
	}

	readPubRsp, err := readPub.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("failed to read NV public: %w", err)
	}

	return &NVIndexInfo{
		Handle: nvHandle,
		Name:   readPubRsp.NVName,
	}, nil
}

// DeleteNVIndex removes an NV index.
func DeleteNVIndex(tpm transport.TPM, nvInfo *NVIndexInfo) error {
	undefineSpace := tpm2.NVUndefineSpace{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth([]byte("")),
		},
		NVIndex: tpm2.NamedHandle{
			Handle: nvInfo.Handle,
			Name:   nvInfo.Name,
		},
	}

	_, err := undefineSpace.Execute(tpm)
	if err != nil {
		return fmt.Errorf("failed to undefine NV space: %w", err)
	}

	return nil
}

// HMACAuth creates an inline HMAC session for authorization using an authValue.
// This session provides authorization through HMAC proof-of-knowledge without
// parameter encryption.
//
// Combine with an encryption session (e.g., salted session) for complete protection:
//   - HMACAuth provides authorization (proves you know the password)
//   - Salted session provides encryption (protects sensitive data on bus)
//
// Session parameters:
//   - Session type: HMAC (inline/ephemeral)
//   - Auth: HMAC with provided authValue
//   - Encryption: None (authorization only)
//
// Example usage:
//
//	// Create authorization session
//	authSess := common.HMACAuth(ownerPassword)
//
//	// Create encryption session
//	encryptSess := salted.Salted(ekHandle, ekPublic)
//
//	// Use both sessions together
//	rsp, err := tpm2.CreatePrimary{
//	    PrimaryHandle: tpm2.AuthHandle{
//	        Handle: tpm2.TPMRHOwner,
//	        Auth:   tpm2.MultiSession(authSess, encryptSess),
//	    },
//	    // ...
//	}.Execute(tpm)
func HMACAuth(authValue []byte) tpm2.Session {
	return tpm2.HMAC(
		tpm2.TPMAlgSHA256,
		16, // nonceCaller size
		tpm2.Auth(authValue),
	)
}
