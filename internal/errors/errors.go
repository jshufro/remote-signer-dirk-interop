package errors

// These errors are manually copied from the spec
type SignerError struct {
	HttpCode int
	Message  string
}

var (
	ErrSlashingProtectionTriggered = &SignerError{
		HttpCode: 412,
		Message:  "slashing protection triggered",
	}
	ErrPublicKeyNotFound = &SignerError{
		HttpCode: 404,
		Message:  "public key not found",
	}
	ErrBadRequest = &SignerError{
		HttpCode: 400,
		Message:  "bad request format",
	}
	ErrInternalServerError = &SignerError{
		HttpCode: 500,
		Message:  "internal server error",
	}
)

func (e *SignerError) Error() string {
	return e.Message
}
