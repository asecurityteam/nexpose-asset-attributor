package assetvalidator

import "strings"

// MultiValidatorError occurs when any validation check has an error.
// MultiValidatorError keeps track of a list of errors.
type MultiValidatorError struct {
	ErrorList []error
	Type      string
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
