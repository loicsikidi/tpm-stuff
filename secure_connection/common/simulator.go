package common

import (
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

// OpenSimulator opens a TPM simulator connection for testing.
// The caller must call Close() on the returned transport.TPMCloser when done.
func OpenSimulator() (transport.TPMCloser, error) {
	return simulator.OpenSimulator()
}
