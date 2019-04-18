package assetattributor

import "fmt"

// AssetNotFoundError occurs when a request to an asset inventory system
// returns a success response, but with no results for a given asset
type AssetNotFoundError struct {
	Inner          error
	AssetID        string
	ScanTimestamp  string
	AssetInventory string
}

func (err AssetNotFoundError) Error() string {
	return fmt.Sprintf(
		"Result not found for asset with ID %v as of scan time %v in asset inventory %v: %v",
		err.AssetID, err.ScanTimestamp, err.AssetInventory, err.Inner)
}

// AssetInventoryRequestError occurs when a request to an asset inventory system
// returns a failure respons
type AssetInventoryRequestError struct {
	Inner          error
	AssetID        string
	ScanTimestamp  string
	AssetInventory string
	Code           int
}

func (err AssetInventoryRequestError) Error() string {
	return fmt.Sprintf(
		"Request to asset inventory %v failed for asset with ID %v as of scan time %v: %v",
		err.AssetInventory, err.AssetID, err.ScanTimestamp, err.Inner)
}
