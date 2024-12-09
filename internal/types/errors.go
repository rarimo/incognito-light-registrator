package types

import (
	"fmt"
)

type DocumentSODErrorKind uint8

const (
	// SAValidateErr is the error kind for Signed Attributes validation error
	SAValidateErr DocumentSODErrorKind = iota
	// PEMFileParseErr is the error kind for PEM file parse error
	PEMFileParseErr
	// PEMFileValidateErr is the error kind for PEM file validation error
	PEMFileValidateErr
	// PEMFilePubKeyErr is the error kind for PEM file public key error
	PEMFilePubKeyErr
	// SigVerifyErr is the error kind for Signature verification error
	SigVerifyErr
)

func (e DocumentSODErrorKind) String() string {
	switch e {
	case SAValidateErr:
		return "Signature Algorithm validation error"
	case PEMFileParseErr:
		return "PEM file parse error"
	case PEMFileValidateErr:
		return "PEM file validation error"
	case SigVerifyErr:
		return "Signature verification error"
	default:
		return "Unknown"
	}
}

func (e DocumentSODErrorKind) Ptr() *DocumentSODErrorKind {
	return &e
}

type SodError struct {
	Kind    *DocumentSODErrorKind
	Message error
}

func (e *SodError) Error() string {
	return fmt.Sprintf("%s: %e", e.Kind, e.Message)
}

func (e *SodError) GetOptionalMessage() *string {
	if e.Message != nil {
		msg := e.Message.Error()
		return &msg
	}
	return nil
}

func (e *SodError) GetOptionalKind() *DocumentSODErrorKind {
	if e.Kind != nil {
		return e.Kind
	}
	return nil
}
