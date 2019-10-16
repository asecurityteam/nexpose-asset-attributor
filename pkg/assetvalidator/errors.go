package assetvalidator

import "strings"

// ValidationError occurs when the process of validation fails
// unexpectantly, and not due to an invalid attributed asset
// Examples of usage would include a bad http call
type ValidationError struct {
	ErrorList []error
}

// ValidationError's Error statement will return
// a conglomeration of all errors that occurred
func (ve ValidationError) Error() string {
	errstrings := make([]string, len(ve.ErrorList))

	for _, err := range ve.ErrorList {
		errstrings = append(errstrings, err.Error())
	}
	return strings.Join(errstrings, "\n")
}

// ValidationFailure occurs when any validation check fails
// validation, in other words an asset is invalid
type ValidationFailure struct {
	FailureList []error
}

// ValidationFailure's Error statement will return
// a conglomeration of all reasons of failure in the FailureList
func (vf ValidationFailure) Error() string {
	errstrings := make([]string, len(vf.FailureList))

	for _, err := range vf.FailureList {
		errstrings = append(errstrings, err.Error())
	}
	return strings.Join(errstrings, "\n")
}
