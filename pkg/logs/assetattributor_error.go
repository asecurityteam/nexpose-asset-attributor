package logs

// AssetNotFoundError occurs when a request to an asset inventory system
// returns a success response, but with no results for a given asset
type AssetNotFoundError struct {
	Message string `logevent:"message,default=attribution-failure"`
	Reason  string `logevent:"reason,default=asset-not-found"`
}

// AssetInventoryRequestError occurs when a request to an asset inventory system
// returns a failure response
type AssetInventoryRequestError struct {
	Message string `logevent:"message,default=attribution-failure"`
	Reason  string `logevent:"reason,default=asset-inventory-request-failed"`
}
