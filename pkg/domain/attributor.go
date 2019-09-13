package domain

import (
	"context"
	"fmt"
	"time"
)

// AssetAttributor receives a NexposeAssetVulnerabilities instance, queries one
// or more asset inventory systems, and returns a NexposeAttributedAssetVulnerabilities
// instance annotated with the business context for the asset at scan time.
type AssetAttributor interface {
	Attribute(ctx context.Context, asset NexposeAssetVulnerabilities) (NexposeAttributedAssetVulnerabilities, error)
}

// NexposeAssetVulnerabilities is a Nexpose asset response payload appended
// with assetVulnerabilityDetails
type NexposeAssetVulnerabilities struct {
	LastScanned     time.Time                   `json:"lastScanned"`
	Hostname        string                      `json:"hostname"`
	ID              int64                       `json:"id"`
	IP              string                      `json:"ip"`
	Vulnerabilities []AssetVulnerabilityDetails `json:"assetVulnerabilityDetails"`
}

// CloudAssetDetails represent a cloud asset and associated metadata
type CloudAssetDetails struct {
	PrivateIPAddresses []string          `json:"privateIPAddresses"`
	PublicIPAddresses  []string          `json:"publicIPAddresses"`
	Hostnames          []string          `json:"hostnames"`
	ResourceType       string            `json:"resourceTypes"`
	AccountID          string            `json:"accountID"`
	Region             string            `json:"region"`
	ARN                string            `json:"arn"`
	Tags               map[string]string `json:"tags"`
}

// NexposeAttributedAssetVulnerabilities is a NexposeAssetVulnerabilities instance combined
// with the business context pertaining to the asset at scan time.
type NexposeAttributedAssetVulnerabilities struct {
	NexposeAssetVulnerabilities
	BusinessContext CloudAssetDetails `json:"businessContext"`
}

// AssetNotFoundError occurs when a request to an asset inventory system
// returns either a 404 Not Found response, or a 200 OK response with no results
type AssetNotFoundError struct {
	Inner          error
	AssetID        string
	ScanTimestamp  string
	AssetInventory string
}

func (err AssetNotFoundError) Error() string {
	return fmt.Sprintf(
		"Result not found for asset with ID %s as of scan time %s in asset inventory %s: %v",
		err.AssetID, err.ScanTimestamp, err.AssetInventory, err.Inner)
}

// AssetInventoryRequestError occurs when a request to an asset inventory system
// returns a failure response
type AssetInventoryRequestError struct {
	Inner          error
	AssetID        string
	ScanTimestamp  string
	AssetInventory string
	Code           int
}

func (err AssetInventoryRequestError) Error() string {
	return fmt.Sprintf(
		"Request to asset inventory %s failed with code %d for asset with ID %s as of scan time %s: %v",
		err.AssetInventory, err.Code, err.AssetID, err.ScanTimestamp, err.Inner)
}

// AssetInventoryMultipleAssetsFoundError occurs when a request to an asset inventory system
// returns a successful response with multiple assets
type AssetInventoryMultipleAssetsFoundError struct {
	Inner          error
	AssetID        string
	ScanTimestamp  string
	AssetInventory string
}

func (err AssetInventoryMultipleAssetsFoundError) Error() string {
	return fmt.Sprintf(
		"Request to asset inventory %s returned multiple values for asset with ID %s as of scan time %s: %v",
		err.AssetInventory, err.AssetID, err.ScanTimestamp, err.Inner)
}

// AttributionFailureHandler is an interface that handles assets that could not be completely
// attributed. The methods to implement might vary organization to organization
type AttributionFailureHandler interface {
	// This method is left to the discretion of the organization. For example, we may want to store their attribution failures encrypted
	// in a persistent store, while others may want to persist theirs in a long-lived encrypted queue, or rely on a streaming platform
	// like Kafka to keep the data until it can be investigated.
	HandleAttributionFailure(ctx context.Context, failedAttributedAsset NexposeAttributedAssetVulnerabilities) error
}
