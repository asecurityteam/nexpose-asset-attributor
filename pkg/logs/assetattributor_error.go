package logs

// AssetNotFoundError occurs when asset attribution fails due to
// either a 404 Not Found response or a 200 OK response with no results
// from the queried asset inventory system(s)
type AssetNotFoundError struct {
	Message string `logevent:"message,default=attribution-failure"`
	Reason  string `logevent:"reason,default=asset-not-found"`
}

// AssetInventoryRequestError occurs when asset attribution fails due to a
// 5XX error response from the queried asset inventory system(s)
type AssetInventoryRequestError struct {
	Message string `logevent:"message,default=attribution-failure"`
	Reason  string `logevent:"reason,default=asset-inventory-request-failed"`
}

// UnknownAttributionFailureError occurs when asset attribution fails for
// an unexpected reason not covered by any other attribution failure error types
type UnknownAttributionFailureError struct {
	Message string `logevent:"message,default=attribution-failure"`
	Reason  string `logevent:"reason,default=unknown-attribution-failure"`
}
