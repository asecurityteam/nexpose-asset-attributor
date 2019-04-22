package domain

import (
	"context"
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
	Asset
	Vulnerabilities []AssetVulnerabilityDetails `json:"assetVulnerabilityDetails"`
}

// CloudAssetDetails represent an asset and associated metadata
type CloudAssetDetails struct {
	PrivateIPAddresses []string          `json:"privateIPAddresses"`
	PublicIPAddresses  []string          `json:"publicIPAddresses"`
	Hostnames          []string          `json:"hostnames"`
	ResourceType       string            `json:"resourceTypes"`
	AccountID          string            `json:"accountID"`
	Region             string            `json:"region"`
	ResourceID         string            `json:"resourceID"`
	Tags               map[string]string `json:"tags"`
}

// NexposeAttributedAssetVulnerabilities is a NexposeAssetVulnerabilities instance combined
// with the business context pertaining to the asset at scan time.
type NexposeAttributedAssetVulnerabilities struct {
	Asset           `json:"asset"`
	Vulnerabilities []AssetVulnerabilityDetails `json:"assetVulnerabilityDetails"`
	BusinessContext CloudAssetDetails           `json:"businessContext"`
}
