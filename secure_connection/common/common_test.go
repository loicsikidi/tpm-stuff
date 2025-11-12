package common_test

import (
	"testing"

	"github.com/loicsikidi/tpm-stuff/secure_connection/common"
	"github.com/stretchr/testify/require"
)

func TestOpenSimulator(t *testing.T) {
	tpm, err := common.OpenSimulator()
	require.NoError(t, err)
	require.NotNil(t, tpm)
	defer tpm.Close()
}

func TestGenerateRandomData(t *testing.T) {
	data, err := common.GenerateRandomData(32)
	require.NoError(t, err)
	require.Len(t, data, 32)

	// Verify randomness by generating another block
	data2, err := common.GenerateRandomData(32)
	require.NoError(t, err)
	require.NotEqual(t, data, data2)
}

func TestCreateAndDeleteNVIndex(t *testing.T) {
	tpm, err := common.OpenSimulator()
	require.NoError(t, err)
	defer tpm.Close()

	// Create NV index
	nvInfo, err := common.CreateNVIndex(tpm, 0x01000000, 32, "testpassword")
	require.NoError(t, err)
	require.NotNil(t, nvInfo)
	require.NotZero(t, nvInfo.Handle)
	require.NotEmpty(t, nvInfo.Name.Buffer)

	// Delete NV index
	err = common.DeleteNVIndex(tpm, nvInfo)
	require.NoError(t, err)
}
