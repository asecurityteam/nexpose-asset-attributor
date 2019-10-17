package assetvalidator

import "strings"

// ValidationFailure occurs when any validation check fails
// validation, in other words an asset is invalid
type ValidationFailure struct {
	AssetID int64
	FailedCheck string
	Inner error
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
