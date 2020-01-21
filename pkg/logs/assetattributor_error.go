package logs

// AssetNotFoundError occurs when asset attribution fails due to
// either a 404 Not Found response or a 200 OK response with no results
// from the queried asset inventory system(s)
type AssetNotFoundError struct {
	Message string `logevent:"message,default=attribution-failure"`
	Reason  string `logevent:"reason,default=asset-not-found"`
	AssetID int64  `logevent:"assetID,default=id-not-specified"`
}

// AssetInventoryRequestError occurs when asset attribution fails due to a
// 5XX error response from the queried asset inventory system(s)
type AssetInventoryRequestError struct {
	Message string `logevent:"message,default=attribution-failure"`
	Reason  string `logevent:"reason,default=asset-inventory-request-failed"`
	AssetID int64  `logevent:"assetID,default=id-not-specified"`
}

// AssetInventoryMultipleAssetsFoundError occurs when asset attribution returns
// more than one result for an asset
type AssetInventoryMultipleAssetsFoundError struct {
	Message string `logevent:"message,default=attribution-failure"`
	Reason  string `logevent:"reason,default=asset-inventory-multiple-assets-found"`
	AssetID int64  `logevent:"assetID,default=id-not-specified"`
}

// UnknownAttributionFailureError occurs when asset attribution fails for
// an unexpected reason not covered by any other attribution failure error types
type UnknownAttributionFailureError struct {
	Message string `logevent:"message,default=attribution-failure"`
	Reason  string `logevent:"reason,default=unknown-attribution-failure"`
	AssetID int64  `logevent:"assetID,default=id-not-specified"`
}

// AssetInventoryMultipleAttributionErrors occurs when asset attribution fails due to
// multiple sources of attribution. This error occurs as a result of a combination of the
// above errors
type AssetInventoryMultipleAttributionErrors struct {
	Message string `logevent:"message,default=attribution-failure"`
	Reason  string `logevent:"reason,default=asset-could-not-attribute-on-sources"`
	AssetID int64  `logevent:"assetID,default=id-not-specified"`
}
