package main

import (
	"flag"
	"log"
	"net"
	"slices"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

var (
	tpmPath = flag.String("tpm-path", "simulator", "Path to the TPM device")
)

var TPMDEVICES = []string{"/dev/tpm0", "/dev/tpmrm0"}

// OpenTPM opens a TPM using the appropriate transport based on the path.
//
// Supported paths:
//   - "/dev/tpm0" or "/dev/tpmrm0": Linux TPM device (linuxtpm)
//   - "simulator": In-process TPM simulator (simulator)
//   - "host:port" (e.g., "127.0.0.1:2321"): TCP connection to swtpm
func OpenTPM(path string) (transport.TPMCloser, error) {
	if slices.Contains(TPMDEVICES, path) {
		return linuxtpm.Open(path)
	} else if path == "simulator" {
		return simulator.OpenSimulator()
	} else {
		// Connect to swtpm over TCP (command port only)
		conn, err := net.Dial("tcp", path)
		if err != nil {
			return nil, err
		}
		return transport.FromReadWriteCloser(conn), nil
	}
}

func main() {
	flag.Parse()

	log.Println("======= Encrypted Session Demo ========")
	log.Println("This demo uses SALTED HMAC session with AES-128 parameter encryption")

	tpm, err := OpenTPM(*tpmPath)
	if err != nil {
		log.Fatalf("can't open TPM: %v", err)
	}
	defer tpm.Close()

	log.Println("Step 1: Creating EK for salt...")

	// First, create EK (Endorsement Key) to use for salted session
	createEK := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
	}

	ekRsp, err := createEK.Execute(tpm)
	if err != nil {
		log.Fatalf("can't create EK: %v", err)
	}
	defer func() {
		flush := tpm2.FlushContext{FlushHandle: ekRsp.ObjectHandle}
		flush.Execute(tpm)
	}()

	ekPub, err := ekRsp.OutPublic.Contents()
	if err != nil {
		log.Fatalf("can't get EK public: %v", err)
	}

	log.Printf("✓ EK created (Handle: 0x%x)", ekRsp.ObjectHandle)

	// The secret password we want to protect
	secretPassword := []byte("MySecretPassword123!")
	log.Printf("Step 2: Creating primary key with password: %s", string(secretPassword))
	log.Println("✅ Using SALTED SESSION - password will be ENCRYPTED on the bus!")

	// Create primary key using SALTED SESSION with encryption
	createPrimary := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth: tpm2.HMAC(
				tpm2.TPMAlgSHA256,
				16,                    // nonce size
				tpm2.Auth([]byte("")), // Owner auth
				tpm2.AESEncryption(128, tpm2.EncryptInOut), // AES-128 parameter encryption
				tpm2.Salted(ekRsp.ObjectHandle, *ekPub),    // Salted with EK
			),
		},
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: secretPassword, // This password is ENCRYPTED on bus!
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
		log.Fatalf("can't create primary: %v", err)
	}

	log.Printf("✓ Primary key created successfully!")
	log.Printf("  Handle: 0x%x", rsp.ObjectHandle)
	log.Println()
	log.Println("🔒 Check the packet capture - password is ENCRYPTED!")
	log.Println("   Look for the TPM2_CreatePrimary command (0x00000131)")
	log.Println("   The InSensitive parameter will show encrypted data")
	log.Println("   You will see:")
	log.Println("     - Session handle in use (0x03xxxxxx)")
	log.Println("     - Encrypted parameter flag set")
	log.Println("     - AES-encrypted data instead of plaintext password")

	// Cleanup
	flush := tpm2.FlushContext{FlushHandle: rsp.ObjectHandle}
	flush.Execute(tpm)

	log.Println("Demo completed.")
}
