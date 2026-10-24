package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/OpenNHP/opennhp/nhp/common"
)

// TestRegistrationResultJSON verifies the result encodes errCode and omits the
// empty optional fields, and that a success result carries "0".
func TestRegistrationResultJSON(t *testing.T) {
	got := RegistrationResult{ErrCode: "0", PublicKey: "PUB"}.JSON()
	for _, want := range []string{`"errCode":"0"`, `"publicKey":"PUB"`} {
		if !strings.Contains(got, want) {
			t.Fatalf("JSON() = %s, missing %q", got, want)
		}
	}
	// Optional fields left empty must be omitted, and the private key must
	// never be emitted unless explicitly set.
	for _, unwanted := range []string{"errMsg", "privateKey", "aspId", "expiresAt"} {
		if strings.Contains(got, unwanted) {
			t.Fatalf("JSON() = %s, should omit %q", got, unwanted)
		}
	}
}

// TestCipherSchemeFor pins the mapping from the SDK cipherType argument to the
// internal cipher-scheme constant: 0 -> Curve25519, 1 -> SM2.
func TestCipherSchemeFor(t *testing.T) {
	if got := cipherSchemeFor(0); got != common.CIPHER_SCHEME_CURVE {
		t.Fatalf("cipherSchemeFor(0) = %d, want %d", got, common.CIPHER_SCHEME_CURVE)
	}
	if got := cipherSchemeFor(1); got != common.CIPHER_SCHEME_GMSM {
		t.Fatalf("cipherSchemeFor(1) = %d, want %d", got, common.CIPHER_SCHEME_GMSM)
	}
}

// TestRegistrationErrorCode returns a coded error's own code, and falls back to
// "1" for a plain error.
func TestRegistrationErrorCode(t *testing.T) {
	if got := registrationErrorCode(common.ErrKnockServerNotFound); got != common.ErrKnockServerNotFound.ErrorCode() {
		t.Fatalf("registrationErrorCode(coded) = %q, want %q", got, common.ErrKnockServerNotFound.ErrorCode())
	}
	if got := registrationErrorCode(fmt.Errorf("plain")); got != "1" {
		t.Fatalf("registrationErrorCode(plain) = %q, want \"1\"", got)
	}
}

// TestConfigTomlExists reports presence of etc/config.toml under the working
// directory.
func TestConfigTomlExists(t *testing.T) {
	dir := t.TempDir()
	if configTomlExists(dir) {
		t.Fatalf("configTomlExists on empty dir = true, want false")
	}
	etc := filepath.Join(dir, "etc")
	if err := os.MkdirAll(etc, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(etc, "config.toml"), []byte("x = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !configTomlExists(dir) {
		t.Fatalf("configTomlExists with config.toml = false, want true")
	}
}

// TestRegisterDevice_InputValidation covers the early-return guards that reject
// bad input before any agent is started or any packet is sent. These paths take
// a nil "current" agent and must never start one.
func TestRegisterDevice_InputValidation(t *testing.T) {
	invalid := common.ErrInvalidInput.ErrorCode()

	// Missing OTP is rejected first.
	if r := RegisterDevice(nil, t.TempDir(), 0, "", 0, "u@x", "d", "org", "", "asp", "res", "cluster", ""); r.ErrCode != invalid {
		t.Fatalf("missing otp: errCode = %q, want %q", r.ErrCode, invalid)
	}
	// Missing required identity fields are rejected.
	if r := RegisterDevice(nil, t.TempDir(), 0, "", 0, "", "d", "org", "", "asp", "res", "cluster", "otp"); r.ErrCode != invalid {
		t.Fatalf("missing email: errCode = %q, want %q", r.ErrCode, invalid)
	}
	// With no running agent and no key, registration cannot proceed.
	if r := RegisterDevice(nil, t.TempDir(), 0, "", 0, "u@x", "d", "org", "", "asp", "res", "cluster", "otp"); r.ErrCode != invalid {
		t.Fatalf("missing private key: errCode = %q, want %q", r.ErrCode, invalid)
	}
}

// TestRequestRegistrationOtp_InputValidation covers the required-field guard for
// the OTP request. A nil "current" agent with missing fields must return the
// invalid-input code without starting an agent.
func TestRequestRegistrationOtp_InputValidation(t *testing.T) {
	invalid := common.ErrInvalidInput.ErrorCode()
	if r := RequestRegistrationOtp(nil, t.TempDir(), 0, "", 0, "", "d", "org", "", "asp", "res", "cluster"); r.ErrCode != invalid {
		t.Fatalf("missing email: errCode = %q, want %q", r.ErrCode, invalid)
	}
}
