package config

// Secret is a string that never reveals its value when printed, logged or
// serialised. Call Value to obtain the plaintext deliberately.
type Secret string

const redacted = "[REDACTED]"

// Value returns the plaintext secret.
func (s Secret) Value() string { return string(s) }

// IsSet reports whether the secret is non-empty.
func (s Secret) IsSet() bool { return s != "" }

func (s Secret) String() string   { return s.mask() }
func (s Secret) GoString() string { return s.mask() }

// MarshalText makes JSON/YAML/zap encoders emit the masked value.
func (s Secret) MarshalText() ([]byte, error) { return []byte(s.mask()), nil }

// UnmarshalText lets config decoders populate the secret.
func (s *Secret) UnmarshalText(b []byte) error {
	*s = Secret(b)
	return nil
}

func (s Secret) mask() string {
	if s == "" {
		return ""
	}
	return redacted
}
