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

var errorKindStrings = map[DocumentSODErrorKind]string{
	SAValidateErr:      "Signature Algorithm validation error",
	PEMFileParseErr:    "PEM file parse error",
	PEMFileValidateErr: "PEM file validation error",
	PEMFilePubKeyErr:   "PEM file public key error",
	SigVerifyErr:       "Signature verification error",
}

var errorKindFields = map[DocumentSODErrorKind]string{
	SAValidateErr:      "/data/attributes/document_sod/signed_attributes",
	PEMFileParseErr:    "/data/attributes/document_sod/pem_file",
	PEMFileValidateErr: "/data/attributes/document_sod/pem_file",
	PEMFilePubKeyErr:   "/data/attributes/document_sod/pem_file",
	SigVerifyErr:       "/data/attributes/document_sod/signature",
}

func (e DocumentSODErrorKind) String() string {
	if msg, ok := errorKindStrings[e]; ok {
		return msg
	}
	return "Unknown"
}

func (e DocumentSODErrorKind) Field() string {
	if field, ok := errorKindFields[e]; ok {
		return field
	}
	return "/"
}

func (e DocumentSODErrorKind) Ptr() *DocumentSODErrorKind {
	return &e
}

type SodError struct {
	Details      *SodErrorDetails
	VerboseError error
}

type SodErrorDetails struct {
	Kind        DocumentSODErrorKind `json:"kind"`
	Description error                `json:"description"`
}

func (e *SodError) Error() string {
	if e.Details == nil {
		return e.VerboseError.Error()
	}

	return fmt.Sprintf("%s: %s", e.Details.Kind.String(), e.Details.Description)
}

func (e *SodError) KindPtr() *DocumentSODErrorKind {
	if e.Details == nil {
		return nil
	}

	return e.Details.Kind.Ptr()
}

func (e *SodError) VerboseErrorPtr() *string {
	if e.VerboseError == nil {
		return nil
	}

	verboseError := e.VerboseError.Error()
	return &verboseError
}
