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

// Salted creates an inline salted HMAC session for parameter encryption.
func Salted(saltKeyHandle tpm2.TPMHandle, saltKeyPublic tpm2.TPMTPublic) tpm2.Session {
	return tpm2.HMAC(
		tpm2.TPMAlgSHA256,
		16, // nonceCaller size
		tpm2.Salted(saltKeyHandle, saltKeyPublic),
		tpm2.AESEncryption(128, tpm2.EncryptInOut),
	)
}

var (
	tpmPath = flag.String("tpm-path", "127.0.0.1:2321", "TPM simulator address")
)

func main() {
	flag.Parse()

	log.Println("======= Complex Hierarchical Keys Demo (ENCRYPTED SESSION) ========")
	log.Println("This demo uses BOTH HMAC authorization AND salted parameter encryption")
	log.Println("Scenario: EK → Owner → Key A → Key B")
	log.Println("")

	tpm, err := OpenTPM(*tpmPath)
	if err != nil {
		log.Fatalf("Failed to open TPM: %v", err)
	}
	defer tpm.Close()

	// Step 1: Create EK for salted encryption sessions
	log.Println("Step 1: Creating Endorsement Key (EK) for salted sessions...")
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

	ekPub, err := ekRsp.OutPublic.Contents()
	if err != nil {
		log.Fatalf("Failed to parse EK public key: %v", err)
	}
	log.Printf("✓ EK created for salted sessions (Handle: 0x%08X)", ekRsp.ObjectHandle)
	log.Println("")

	// Create the encryption session (reusable across all operations)
	log.Println("Creating salted encryption session (AES-128-CFB)...")
	encryptSess := Salted(ekRsp.ObjectHandle, *ekPub)
	log.Println("✓ Encryption session created (will be reused for all operations)")
	log.Println("")

	// Step 2: Create primary key A under Owner hierarchy with password
	keyAPassword := []byte("passwordA")
	log.Printf("Step 2: Creating primary key A with password: %s", string(keyAPassword))
	log.Println("✅ Password will be ENCRYPTED on the bus using salted session!")

	authSessOwner := HMACAuth([]byte("")) // Owner has empty password

	createPrimaryA := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   authSessOwner, // Session 1: HMAC authorization
		},
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: keyAPassword, // Will be encrypted by encryptSess
				},
			},
		},
		InPublic: tpm2.New2B(tpm2.ECCSRKTemplate),
	}

	// Pass encryption session to Execute() - Session 2: Parameter encryption
	keyARsp, err := createPrimaryA.Execute(tpm, encryptSess)
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
	log.Println("✅ Password will be ENCRYPTED on the bus using salted session!")

	authSessKeyA := HMACAuth(keyAPassword) // Prove we know key A's password

	createKeyB := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{
			Handle: keyARsp.ObjectHandle,
			Name:   keyARsp.Name,
			Auth:   authSessKeyA, // Session 1: HMAC authorization
		},
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: keyBPassword, // Will be encrypted by encryptSess
				},
			},
		},
		InPublic: tpm2.New2B(tpm2.ECCSRKTemplate),
	}

	// Pass encryption session to Execute() - Session 2: Parameter encryption
	keyBRsp, err := createKeyB.Execute(tpm, encryptSess)
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
			Auth:   authSessKeyA, // Session 1: HMAC authorization
		},
		InPrivate: keyBRsp.OutPrivate,
		InPublic:  keyBRsp.OutPublic,
	}

	// Pass encryption session to Execute() - Session 2: Parameter encryption
	loadKeyBRsp, err := loadKeyB.Execute(tpm, encryptSess)
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
	log.Println("✓ Key hierarchy created with FULL security: EK → Owner → A → B")
	log.Println("")
	log.Println("🔐 SECURITY ANALYSIS:")
	log.Println("  ✅ Authorization: HMAC sessions (proves password knowledge)")
	log.Println("     - authSessOwner: proves knowledge of Owner password (empty)")
	log.Println("     - authSessKeyA: proves knowledge of key A password ('passwordA')")
	log.Println("")
	log.Println("  ✅ Encryption: Salted session with AES-128-CFB")
	log.Println("     - encryptSess: encrypts ALL sensitive parameters")
	log.Println("     - 'passwordA' encrypted when creating key A")
	log.Println("     - 'xoxo' encrypted when creating key B")
	log.Println("     - Same session reused for all operations (efficient!)")
	log.Println("")
	log.Println("=== Session Design ===")
	log.Println("Each command used TWO sessions:")
	log.Println("  1. Authorization session (HMAC) via AuthHandle.Auth")
	log.Println("     → Proves we know the password (without revealing it)")
	log.Println("  2. Encryption session (salted) via Execute(...session)")
	log.Println("     → Encrypts sensitive parameters on the TPM bus")
	log.Println("")
	log.Println("🔍 Check the packet capture:")
	log.Println("   Look for TPM2_CreatePrimary (0x00000131) and TPM2_Create (0x00000153)")
	log.Println("   Passwords will be ENCRYPTED - unreadable ciphertext!")
	log.Println("")
	log.Println("Demo completed.")
}
