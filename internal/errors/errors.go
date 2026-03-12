package errors

import "fmt"

type SignerError = *signerError

type signerError struct {
	// Code is a machine-readable error code suitable for clients.
	Code string
	// HttpCode is the HTTP status code that should be returned.
	HttpCode int
	// Message is a human-readable description of the error.
	Message error
}

const (
	SlashingProtectionTriggeredCode = "slashing_protection_triggered"
	PublicKeyNotFoundCode           = "public_key_not_found"
	BadRequestCode                  = "bad_request"
	InternalServerErrorCode         = "internal_server_error"

	SlashingProtectionTriggeredHttpCode = 412
	PublicKeyNotFoundHttpCode           = 404
	BadRequestHttpCode                  = 400
	InternalServerErrorHttpCode         = 500
)

func (e *signerError) Error() string {
	if e.Message == nil {
		return fmt.Sprintf("%s", e.Code)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func SlashingProtectionTriggered(fmtStr string, args ...any) SignerError {
	return &signerError{
		Code:     SlashingProtectionTriggeredCode,
		HttpCode: SlashingProtectionTriggeredHttpCode,
		Message:  fmt.Errorf(fmtStr, args...),
	}
}

func PublicKeyNotFound(fmtStr string, args ...any) SignerError {
	return &signerError{
		Code:     PublicKeyNotFoundCode,
		HttpCode: PublicKeyNotFoundHttpCode,
		Message:  fmt.Errorf(fmtStr, args...),
	}
}

func BadRequest(fmtStr string, args ...any) SignerError {
	return &signerError{
		Code:     BadRequestCode,
		HttpCode: BadRequestHttpCode,
		Message:  fmt.Errorf(fmtStr, args...),
	}
}

func InternalServerError() SignerError {
	return &signerError{
		Code:     InternalServerErrorCode,
		HttpCode: InternalServerErrorHttpCode,
		Message:  nil,
	}
}
