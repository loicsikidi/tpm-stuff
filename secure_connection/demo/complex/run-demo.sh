#!/usr/bin/env bash
set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}======================================${NC}"
echo -e "${BLUE}TPM Hierarchical Keys Demo${NC}"
echo -e "${BLUE}Complex Scenario: EK → Owner → A → B${NC}"
echo -e "${BLUE}======================================${NC}"
echo ""

# Request sudo access upfront for tcpdump
echo -e "${YELLOW}This demo requires sudo access for packet capture.${NC}"
echo -e "${YELLOW}Please enter your password if prompted:${NC}"
sudo -v || {
    echo -e "${RED}Error: sudo access required${NC}"
    exit 1
}
echo ""

# Check for required tools
check_tool() {
    if ! command -v "$1" &> /dev/null; then
        echo -e "${RED}Error: $1 is not installed${NC}"
        echo "Please install: $2"
        exit 1
    fi
}

check_tool "swtpm" "swtpm (apt install swtpm or brew install swtpm)"
check_tool "tcpdump" "tcpdump (apt install tcpdump or brew install tcpdump)"
check_tool "tpm2_pcrread" "tpm2-tools (apt install tpm2-tools or brew install tpm2-tools)"

# Cleanup function
cleanup() {
    echo ""
    echo -e "${YELLOW}Cleaning up...${NC}"

    # Kill swtpm if running
    if [ ! -z "${SWTPM_PID:-}" ]; then
        kill $SWTPM_PID 2>/dev/null || true
    fi

    # Kill tcpdump if running
    if [ ! -z "${TCPDUMP_PID:-}" ]; then
        sudo kill $TCPDUMP_PID 2>/dev/null || true
    fi

    # Remove temp directory
    rm -rf /tmp/tpm-demo-$$

    echo -e "${GREEN}Cleanup complete${NC}"
}

trap cleanup EXIT INT TERM

# Create temp directory for TPM state
TMPDIR="/tmp/tpm-demo-$$"
mkdir -p "$TMPDIR"

echo -e "${GREEN}Step 1: Starting swtpm simulator on TCP port 2321...${NC}"
swtpm socket \
    --tpmstate dir="$TMPDIR" \
    --tpm2 \
    --server type=tcp,port=2321 \
    --ctrl type=tcp,port=2322 \
    --flags not-need-init,startup-clear \
    --log level=0 &
SWTPM_PID=$!

# Wait for swtpm to be ready
sleep 2

# Test TPM connection
export TPM2TOOLS_TCTI="swtpm:port=2321"
if ! tpm2_pcrread sha256:0 &>/dev/null; then
    echo -e "${RED}Error: swtpm is not responding${NC}"
    exit 1
fi

echo -e "${GREEN}✓ swtpm is running (PID: $SWTPM_PID)${NC}"
echo ""

# Function to build demo if binary doesn't exist
build_demo_if_needed() {
    local DEMO_DIR=$1
    local BINARY_NAME="demo-$(basename "$DEMO_DIR")"

    if [ ! -f "$DEMO_DIR/$BINARY_NAME" ]; then
        echo -e "${YELLOW}Binary $BINARY_NAME not found, building...${NC}"
        (cd "$DEMO_DIR" && go build -o "$BINARY_NAME" .) || {
            echo -e "${RED}Error: Failed to build $BINARY_NAME${NC}"
            exit 1
        }
        echo -e "${GREEN}✓ Built $BINARY_NAME${NC}"
        echo ""
    fi
}

# Function to run demo with capture
run_demo() {
    local TYPE=$1
    local DEMO_DIR=$2
    local CAP_FILE=$3

    echo -e "${BLUE}======================================${NC}"
    echo -e "${BLUE}Running: ${TYPE} Demo${NC}"
    echo -e "${BLUE}======================================${NC}"
    echo ""

    # Build demo if needed
    build_demo_if_needed "$DEMO_DIR"

    # Start tcpdump
    echo -e "${YELLOW}Starting packet capture...${NC}"
    sudo tcpdump -s0 -i lo -w "$CAP_FILE" port 2321 &>/dev/null &
    TCPDUMP_PID=$!
    sleep 2
    echo -e "${GREEN}✓ tcpdump started (PID: $TCPDUMP_PID)${NC}"
    echo ""

    # Run the demo
    echo -e "${GREEN}Executing demo program...${NC}"
    echo ""
    (cd "$DEMO_DIR" && ./demo-$(basename "$DEMO_DIR") -tpm-path="127.0.0.1:2321")

    # Wait for tcpdump to flush buffers
    sleep 1

    # Stop tcpdump
    echo ""
    echo -e "${YELLOW}Stopping packet capture...${NC}"
    sudo kill $TCPDUMP_PID 2>/dev/null || true
    sleep 1
    TCPDUMP_PID=""

    # Check capture file
    if [ -f "$CAP_FILE" ]; then
        local PACKET_COUNT=$(tcpdump -r "$CAP_FILE" 2>/dev/null | wc -l)
        echo -e "${GREEN}✓ Captured $PACKET_COUNT packets to: $CAP_FILE${NC}"
    else
        echo -e "${RED}✗ Capture file not created${NC}"
    fi

    echo ""
}

# Run plaintext demo
run_demo "PLAINTEXT (NO ENCRYPTION)" \
    "$(dirname "$0")/plaintext" \
    "$(dirname "$0")/plaintext.cap"

echo ""
echo -e "${YELLOW}Press Enter to continue to encrypted demo...${NC}"
read -r

# Run encrypted demo
run_demo "ENCRYPTED SESSION" \
    "$(dirname "$0")/encrypted" \
    "$(dirname "$0")/encrypted.cap"

echo ""
echo -e "${BLUE}======================================${NC}"
echo -e "${BLUE}Demo Complete!${NC}"
echo -e "${BLUE}======================================${NC}"
echo ""
echo -e "${GREEN}Capture files created:${NC}"
echo -e "  📄 Plaintext:  $(dirname "$0")/plaintext.cap"
echo -e "  📄 Encrypted:  $(dirname "$0")/encrypted.cap"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo -e "1. Open capture files in Wireshark"
echo -e "2. Filter for: tpm"
echo -e "3. Look for TPM2_CreatePrimary (0x00000131) and TPM2_Create (0x00000153) commands"
echo -e "4. Compare InSensitive parameters:"
echo -e "   ${RED}• plaintext.cap${NC}  - Passwords 'passwordA' and 'xoxo' visible in CLEAR TEXT"
echo -e "   ${GREEN}• encrypted.cap${NC} - Passwords encrypted with AES-128-CFB, unreadable"
echo ""
echo -e "To analyze with tshark:"
echo -e "  tshark -r $(dirname "$0")/plaintext.cap -Y tpm -V | grep -A30 'CreatePrimary\\|Create'"
echo -e "  tshark -r $(dirname "$0")/encrypted.cap -Y tpm -V | grep -A30 'CreatePrimary\\|Create'"
echo ""
