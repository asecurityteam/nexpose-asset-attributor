package logs

import "github.com/asecurityteam/nexpose-asset-attributor/pkg/domain"

// AssetValidationFailure occurs when an asset was found in an asset inventory system
// and subsequent validation of that asset completed, but with a failure result.
type AssetValidationFailure struct {
	Message      string `logevent:"message,default=validation-failure"`
	Reason       string `logevent:"reason,default=unknown-validation-failure"`
	AssetID      int64  `logevent:"assetID,default=id-not-specified"`
	ResourceID   string `logevent:"resourceID,default=resourceID-not-specified"`
	ResourceType string `logevent:"resourcetype,default=unknown-resourcetype"`
}

// AssetValidationError occurs when an asset was found in an asset inventory system
// and subsequent validation of that asset could not complete due to an unexpected error.
type AssetValidationError struct {
	Message string `logevent:"message,default=validation-error"`
	Reason  string `logevent:"reason,default=unknown-validation-error"`
	AssetID int64  `logevent:"assetID,default=id-not-specified"`
}

// ValidationErrorLogFactory is a factory function that takes an error that occurs during validation,
// and returns a corresponding struct with logging information
func ValidationErrorLogFactory(validationErr error, assetID int64, resourceID string, resourceType string) interface{} {
	switch validationErr.(type) {
	case domain.ValidationFailure:
		return AssetValidationFailure{Reason: validationErr.Error(), AssetID: assetID, ResourceID: resourceID, ResourceType: resourceType}
	default:
		return AssetValidationError{Reason: validationErr.Error(), AssetID: assetID}
	}
}
