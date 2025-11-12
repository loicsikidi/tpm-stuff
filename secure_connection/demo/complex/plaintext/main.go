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

// HMACAuth creates an inline HMAC session for authorization using an authValue.
func HMACAuth(authValue []byte) tpm2.Session {
	return tpm2.HMAC(
		tpm2.TPMAlgSHA256,
		16, // nonceCaller size
		tpm2.Auth(authValue),
	)
}

var (
	tpmPath = flag.String("tpm-path", "127.0.0.1:2321", "TPM simulator address")
)

func main() {
	flag.Parse()

	log.Println("======= Complex Hierarchical Keys Demo (PLAINTEXT - NO ENCRYPTION) ========")
	log.Println("This demo uses HMAC sessions for authorization but NO parameter encryption")
	log.Println("Scenario: EK → Owner → Key A → Key B")
	log.Println("")

	tpm, err := OpenTPM(*tpmPath)
	if err != nil {
		log.Fatalf("Failed to open TPM: %v", err)
	}
	defer tpm.Close()

	// Step 1: Create EK (for demonstration purposes, not used for encryption here)
	log.Println("Step 1: Creating Endorsement Key (EK)...")
	createEK := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHEndorsement,
			Auth:   tpm2.PasswordAuth([]byte("")),
		},
		InPublic: tpm2.New2B(tpm2.RSAEKTemplate),
	}

	ekRsp, err := createEK.Execute(tpm)
	if err != nil {
		log.Fatalf("Failed to create EK: %v", err)
	}
	defer func() {
		flush := tpm2.FlushContext{FlushHandle: ekRsp.ObjectHandle}
		flush.Execute(tpm)
	}()
	log.Printf("✓ EK created (Handle: 0x%08X)", ekRsp.ObjectHandle)
	log.Println("")

	// Step 2: Create primary key A under Owner hierarchy with password
	keyAPassword := []byte("passwordA")
	log.Printf("Step 2: Creating primary key A with password: %s", string(keyAPassword))
	log.Println("⚠️  WARNING: Password will be visible in plaintext on the bus!")

	authSessOwner := HMACAuth([]byte("")) // Owner has empty password

	createPrimaryA := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   authSessOwner, // HMAC proves we know Owner password
		},
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: keyAPassword, // NOT encrypted - visible on bus!
				},
			},
		},
		InPublic: tpm2.New2B(tpm2.ECCSRKTemplate),
	}

	// NO encryption session passed to Execute()
	keyARsp, err := createPrimaryA.Execute(tpm)
	if err != nil {
		log.Fatalf("Failed to create primary key A: %v", err)
	}
	defer func() {
		flush := tpm2.FlushContext{FlushHandle: keyARsp.ObjectHandle}
		flush.Execute(tpm)
	}()
	log.Printf("✓ Primary key A created (Handle: 0x%08X)", keyARsp.ObjectHandle)
	log.Println("")

	// Step 3: Create key B (child of A) with password "xoxo"
	keyBPassword := []byte("xoxo")
	log.Printf("Step 3: Creating key B (child of A) with password: %s", string(keyBPassword))
	log.Println("⚠️  WARNING: Password will be visible in plaintext on the bus!")

	authSessKeyA := HMACAuth(keyAPassword) // Prove we know key A's password

	createKeyB := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{
			Handle: keyARsp.ObjectHandle,
			Name:   keyARsp.Name,
			Auth:   authSessKeyA, // HMAC proves we know key A password
		},
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: keyBPassword, // NOT encrypted - visible on bus!
				},
			},
		},
		InPublic: tpm2.New2B(tpm2.ECCSRKTemplate),
	}

	// NO encryption session passed to Execute()
	keyBRsp, err := createKeyB.Execute(tpm)
	if err != nil {
		log.Fatalf("Failed to create key B: %v", err)
	}
	log.Printf("✓ Key B created successfully")
	log.Println("")

	// Step 4: Load key B
	log.Println("Step 4: Loading key B into TPM...")
	loadKeyB := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: keyARsp.ObjectHandle,
			Name:   keyARsp.Name,
			Auth:   authSessKeyA, // Still need to auth to key A
		},
		InPrivate: keyBRsp.OutPrivate,
		InPublic:  keyBRsp.OutPublic,
	}

	loadKeyBRsp, err := loadKeyB.Execute(tpm)
	if err != nil {
		log.Fatalf("Failed to load key B: %v", err)
	}
	defer func() {
		flush := tpm2.FlushContext{FlushHandle: loadKeyBRsp.ObjectHandle}
		flush.Execute(tpm)
	}()
	log.Printf("✓ Key B loaded (Handle: 0x%08X)", loadKeyBRsp.ObjectHandle)
	log.Println("")

	// Summary
	log.Println("=== Summary ===")
	log.Println("✓ Key hierarchy created: EK → Owner → A → B")
	log.Println("")
	log.Println("🔍 SECURITY ANALYSIS:")
	log.Println("  ✅ Authorization: HMAC sessions proved we know passwords")
	log.Println("     - authSessOwner: proves knowledge of Owner password (empty)")
	log.Println("     - authSessKeyA: proves knowledge of key A password ('passwordA')")
	log.Println("")
	log.Println("  ❌ Encryption: NONE - All passwords sent in PLAINTEXT!")
	log.Println("     - 'passwordA' visible when creating key A")
	log.Println("     - 'xoxo' visible when creating key B")
	log.Println("")
	log.Println("🔍 Check the packet capture:")
	log.Println("   Look for TPM2_CreatePrimary (0x00000131) and TPM2_Create (0x00000153)")
	log.Println("   You will see the passwords in cleartext in InSensitive parameters!")
	log.Println("")
	log.Println("Demo completed.")
}
