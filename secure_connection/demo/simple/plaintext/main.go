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

	log.Println("======= Plaintext Demo (NO ENCRYPTION) ========")
	log.Println("This demo uses PasswordAuth - secrets transmitted in CLEAR TEXT")

	tpm, err := OpenTPM(*tpmPath)
	if err != nil {
		log.Fatalf("can't open TPM: %v", err)
	}
	defer tpm.Close()

	// The secret password we want to protect
	secretPassword := []byte("MySecretPassword123!")
	log.Printf("Creating primary key with password: %s", string(secretPassword))
	log.Println("⚠️  WARNING: Password will be visible in plaintext on the bus!")

	// Create primary key using PASSWORD AUTH (no encryption)
	createPrimary := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth([]byte("")), // Owner auth - plaintext!
		},
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: secretPassword, // This password is PLAINTEXT on bus!
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
	log.Println("🔍 Check the packet capture - you will see the password in PLAINTEXT!")
	log.Println("   Look for the TPM2_CreatePrimary command (0x00000131)")
	log.Println("   The password bytes will be visible in the InSensitive parameter")

	// Cleanup
	flush := tpm2.FlushContext{FlushHandle: rsp.ObjectHandle}
	flush.Execute(tpm)

	log.Println("Demo completed.")
}
