package assetvalidator

import "strings"

// MultiValidatorError occurs when any validation check has an error.
// MultiValidatorError keeps track of a list of errors.
type MultiValidatorError struct {
	ErrorList []error
}

// MultiValidatorError's Error statement will return
// a conglomeration of all errors in the error list
func (mve MultiValidatorError) Error() string {
	errstrings := make([]string, len(mve.ErrorList))

	for _, err := range mve.ErrorList {
		errstrings = append(errstrings, err.Error())
	}
	return strings.Join(errstrings, "\n")
}

// ValidationFailure occurs when the process of validation fails
// unexpectantly, and not due to an invalid attributed asset
// Examples of usage would include a bad http call
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
