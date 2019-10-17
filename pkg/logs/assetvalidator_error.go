package logs

// AssetValidationFailure occurs when an asset was found in an asset inventory system
// and subsequent validation of that asset completed, but with a failure result.
type AssetValidationFailure struct {
	Message string `logevent:"message,default=validation-failure"`
	Reason  string `logevent:"reason,default=unknown-validation-failure"`
}

// AssetValidationError occurs when an asset was found in an asset inventory system
// and subsequent validation of that asset could not complete due to an unexpected error.
type AssetValidationError struct {
	Message string `logevent:"message,default=validation-error"`
	Reason  string `logevent:"reason,default=unknown-validation-error"`
}
