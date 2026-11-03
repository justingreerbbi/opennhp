package agent

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
)

// RegistrationResult is the OTP and device-registration outcome shared by the
// iOS and Android SDK wrappers. It deliberately carries no private key: the
// result is serialized to JSON and handed to the platform layer, where it may
// be logged or captured in a crash report, so a secret must never travel in it.
type RegistrationResult struct {
	ErrCode       string `json:"errCode"`
	ErrMsg        string `json:"errMsg,omitempty"`
	PublicKey     string `json:"publicKey,omitempty"`
	AuthServiceId string `json:"aspId,omitempty"`
	ExpiresAt     *int64 `json:"expiresAt,omitempty"`
}

// JSON encodes the result. A marshal failure becomes a fixed error object.
func (r RegistrationResult) JSON() string {
	bytes, err := json.Marshal(r)
	if err != nil {
		return `{"errCode":"1","errMsg":"failed to encode registration result"}`
	}
	return string(bytes)
}

func registrationErrorCode(err error) string {
	type coder interface{ ErrorCode() string }
	if coded, ok := err.(coder); ok {
		if code := coded.ErrorCode(); code != "" {
			return code
		}
	}
	return "1"
}

func cipherSchemeFor(cipherType int) int {
	if core.EccTypeEnum(cipherType) == core.ECC_SM2 {
		return common.CIPHER_SCHEME_GMSM
	}
	return common.CIPHER_SCHEME_CURVE
}

// validRegistrationCipherType accepts only the two schemes the SDK documents:
// 0 = Curve25519, 1 = SM2. cipherSchemeFor maps everything else (ECC_UMI,
// garbage) to Curve silently, so callers reject the rest up front rather than
// start an agent under a scheme the caller never asked for.
func validRegistrationCipherType(cipherType int) bool {
	return cipherType == int(core.ECC_CURVE25519) || cipherType == int(core.ECC_SM2)
}

// AgentHoldsRegistrationKey reports whether a's current device identity is the
// one that privateKeyBase64 + cipherType would produce. It compares derived
// PUBLIC keys, not the raw config string, so an agent started from a sealed key
// still matches the plaintext key the caller supplies, and the SDK init-with-key
// path can tell "already holds this key" from "holds a different key". Any
// uncertainty (nil agent/config, bad base64, unsupported key, scheme mismatch,
// or no device yet) returns false, which routes callers to the safe "close the
// agent first" path. The device is read only through the deviceMutex-guarded
// PublicKeyBase64ByCipherScheme (which returns "" when there is none), never
// directly here, so this stays race-free against a device swap.
func AgentHoldsRegistrationKey(a *UdpAgent, privateKeyBase64 string, cipherType int) bool {
	if a == nil || a.config == nil || privateKeyBase64 == "" {
		return false
	}
	if !validRegistrationCipherType(cipherType) {
		return false
	}
	if agentCipherScheme(a) != cipherSchemeFor(cipherType) {
		return false
	}
	priv, err := base64.StdEncoding.DecodeString(privateKeyBase64)
	if err != nil {
		return false
	}
	ecc := core.ECC_CURVE25519
	if core.EccTypeEnum(cipherType) == core.ECC_SM2 {
		ecc = core.ECC_SM2
	}
	e := core.ECDHFromKey(ecc, priv)
	if e == nil {
		return false
	}
	pub := e.PublicKeyBase64()
	return pub != "" && pub == a.PublicKeyBase64ByCipherScheme()
}

// StartWithKey starts an agent in memory config mode with privateKey (base64)
// and cipherType (0 Curve25519, 1 SM2), for an SDK that keeps the key in the
// platform secure store. Nothing in workingDir/etc is read and no watcher is
// armed, so no config.toml can replace the key, scheme or identity later;
// workingDir is used only for logs. Servers and resources are added in code
// afterwards (AddServer, AddResource), as is the knock identity (SetKnockUser).
func StartWithKey(workingDir string, logLevel int, privateKey string, cipherType int) (*UdpAgent, error) {
	if workingDir == "" {
		return nil, fmt.Errorf("working directory is required")
	}
	if privateKey == "" {
		return nil, fmt.Errorf("privateKey is required")
	}
	if !validRegistrationCipherType(cipherType) {
		return nil, fmt.Errorf("cipherType must be 0 (Curve25519) or 1 (SM2)")
	}
	if _, err := base64.StdEncoding.DecodeString(privateKey); err != nil {
		return nil, fmt.Errorf("private key is not valid base64")
	}
	instance := &UdpAgent{}
	instance.UseInMemoryConfig(&Config{
		LogLevel:            logLevel,
		DefaultCipherScheme: cipherSchemeFor(cipherType),
		PrivateKeyBase64:    privateKey,
	})
	if err := instance.Start(workingDir, logLevel); err != nil {
		return nil, err
	}
	return instance, nil
}

func agentCipherScheme(a *UdpAgent) int {
	if a == nil || a.config == nil {
		return common.CIPHER_SCHEME_CURVE
	}
	// GetCipherScheme reads under keyMu; ReinitWithKey and, in file mode, the
	// config watcher (updateBaseConfig -> SetCipherScheme) write
	// DefaultCipherScheme under the same lock, so a bare field read would race.
	return a.config.GetCipherScheme()
}

func invalidRegistration(msg string) RegistrationResult {
	return RegistrationResult{
		ErrCode: common.ErrInvalidInput.ErrorCode(),
		ErrMsg:  msg,
	}
}

func applyRegistrationUser(a *UdpAgent, email string, deviceId string, orgId string, userData string) error {
	data := map[string]any{}
	if userData != "" {
		if err := json.Unmarshal([]byte(userData), &data); err != nil {
			return fmt.Errorf("userData is not valid JSON")
		}
	}
	if email != "" {
		data["email"] = email
	}
	a.SetDeviceId(deviceId)
	a.SetKnockUser(email, orgId, data)
	return nil
}

func registrationTarget(a *UdpAgent, aspId string, resId string, cluster string) (*KnockTarget, error) {
	resource := &KnockResource{
		AuthServiceId: aspId,
		ResourceId:    resId,
		Cluster:       cluster,
	}
	sc, err := a.FindServerClusterFromResource(resource)
	if err != nil {
		return nil, err
	}
	if sc == nil {
		return nil, common.ErrKnockServerNotFound
	}
	return &KnockTarget{
		KnockResource: *resource,
		ServerPeer:    sc.RepresentativePeer(),
		ServerCluster: sc,
	}, nil
}

// prepareRegistration checks the inputs, applies the registration identity to
// the running agent, and resolves the target server. Registration always runs
// on the caller's initialized agent (StartWithKey, then AddServer): it never
// starts a second agent and never re-keys the one it is given.
func prepareRegistration(a *UdpAgent, email string, deviceId string, orgId string, userData string, aspId string, resId string, cluster string) (RegistrationResult, *KnockTarget) {
	if email == "" || aspId == "" || resId == "" || cluster == "" {
		return invalidRegistration("email, aspId, resId, and cluster are required"), nil
	}
	if a == nil || !a.IsRunning() {
		return invalidRegistration("initialize the agent with its key and add its server before registering"), nil
	}
	if err := applyRegistrationUser(a, email, deviceId, orgId, userData); err != nil {
		return invalidRegistration(err.Error()), nil
	}
	result := RegistrationResult{
		PublicKey: a.PublicKeyBase64ByCipherScheme(),
	}
	target, err := registrationTarget(a, aspId, resId, cluster)
	if err != nil {
		result.ErrCode = registrationErrorCode(err)
		result.ErrMsg = err.Error()
		return result, nil
	}
	return result, target
}

// knockIdentity is a value snapshot of the agent fields that
// applyRegistrationUser overwrites, so the register flow can put the agent back
// the way it found it.
type knockIdentity struct {
	hadUser  bool
	user     KnockUser
	deviceId string
}

// snapshotKnockIdentity copies a's knock user and device id under
// knockUserMutex. It takes a value copy, not the *KnockUser pointer, because
// SetKnockUser overwrites that struct's fields in place — a captured pointer
// would just observe the overwrite.
func snapshotKnockIdentity(a *UdpAgent) knockIdentity {
	a.knockUserMutex.Lock()
	defer a.knockUserMutex.Unlock()
	snap := knockIdentity{deviceId: a.deviceId}
	if a.knockUser != nil {
		snap.hadUser = true
		snap.user = *a.knockUser
	}
	return snap
}

// restoreKnockIdentity puts a snapshot back. It goes through SetKnockUser, not
// a direct write, because in memory mode SetKnockUser also records the
// identity in the restart template: applyRegistrationUser wrote the
// registration identity there, and a direct write would leave it for the next
// restart to come back with.
func restoreKnockIdentity(a *UdpAgent, snap knockIdentity) {
	a.SetDeviceId(snap.deviceId)
	if snap.hadUser {
		a.SetKnockUser(snap.user.UserId, snap.user.OrganizationId, snap.user.UserData)
	}
}

// RequestRegistrationOtp sends NHP-OTP for the running agent's key; the server
// emails the code to email. The agent keeps its knock identity: the
// registration identity is applied only for this request.
func RequestRegistrationOtp(a *UdpAgent, email string, deviceId string, orgId string, userData string, aspId string, resId string, cluster string) RegistrationResult {
	// prepareRegistration -> applyRegistrationUser overwrites the agent's knock
	// identity. Snapshot it now and restore it on return so the agent keeps
	// knocking as before. RequestOtp copies the identity into the message before
	// it returns, so the restore cannot change what is sent. (A knock racing this
	// call still sees the temporary identity for the duration, which is
	// acceptable for the serial register-then-knock SDK flow.)
	if a != nil && a.IsRunning() {
		snap := snapshotKnockIdentity(a)
		defer restoreKnockIdentity(a, snap)
	}
	result, target := prepareRegistration(a, email, deviceId, orgId, userData, aspId, resId, cluster)
	if target == nil {
		return result
	}
	if err := a.RequestOtp(target); err != nil {
		result.ErrCode = registrationErrorCode(err)
		result.ErrMsg = err.Error()
		return result
	}
	result.ErrCode = common.ErrSuccess.ErrorCode()
	return result
}

// RegisterDevice submits the one-time password from RequestRegistrationOtp to
// register the running agent's public key. Like RequestRegistrationOtp, it
// leaves the agent's knock identity as it was.
func RegisterDevice(a *UdpAgent, email string, deviceId string, orgId string, userData string, aspId string, resId string, cluster string, otp string) RegistrationResult {
	if otp == "" {
		return invalidRegistration("otp is required")
	}
	if a != nil && a.IsRunning() {
		snap := snapshotKnockIdentity(a)
		defer restoreKnockIdentity(a, snap)
	}
	result, target := prepareRegistration(a, email, deviceId, orgId, userData, aspId, resId, cluster)
	if target == nil {
		return result
	}
	ack, err := a.RegisterPublicKey(otp, target)
	if ack != nil {
		result.ErrCode = ack.ErrCode
		result.ErrMsg = ack.ErrMsg
		result.AuthServiceId = ack.AuthServiceId
		result.ExpiresAt = ack.ExpiresAt
	}
	if err != nil && result.ErrCode == "" {
		result.ErrCode = registrationErrorCode(err)
		result.ErrMsg = err.Error()
	}
	if result.ErrCode == "" {
		result.ErrCode = common.ErrSuccess.ErrorCode()
	}
	return result
}
