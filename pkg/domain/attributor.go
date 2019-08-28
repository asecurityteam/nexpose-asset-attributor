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
	Hostname        string                      `json:"hostname,omitempty"`
	ID              int64                       `json:"id"`
	IP              string                      `json:"ip,omitempty"`
	Vulnerabilities []AssetVulnerabilityDetails `json:"assetVulnerabilityDetails"`
}

// CloudAssetDetails represent a cloud asset and associated metadata
type CloudAssetDetails struct {
	PrivateIPAddresses []string          `json:"privateIPAddresses,omitempty"`
	PublicIPAddresses  []string          `json:"publicIPAddresses,omitempty"`
	Hostnames          []string          `json:"hostnames,omitempty"`
	ResourceType       string            `json:"resourceTypes,omitempty"`
	AccountID          string            `json:"accountID,omitempty"`
	Region             string            `json:"region,omitempty"`
	ARN                string            `json:"arn,omitempty"`
	Tags               map[string]string `json:"tags,omitempty"`
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
