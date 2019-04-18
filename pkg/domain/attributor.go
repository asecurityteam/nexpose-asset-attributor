package domain

import "github.com/asecurityteam/nexpose-asset-attributor/pkg/domain/nexpose"

// AssetAttributor receives a NexposeAssetVulnerabilities instance, queries one
// or more asset inventory systems, and returns a NexposeAttributedAssetVulnerabilities
// instance annotated with the business context for the asset at scan time.
type AssetAttributor interface {
	Attribute(asset NexposeAssetVulnerabilities) (NexposeAttributedAssetVulnerabilities, error)
}

// NexposeAssetVulnerabilities is a Nexpose asset response payload appended
// with assetVulnerabilityDetails
type NexposeAssetVulnerabilities struct {
	nexpose.Asset
	Vulnerabilities []nexpose.AssetVulnerabilityDetails `json:"assetVulnerabilityDetails"`
}

// CloudAssetDetails represent an asset and associated metadata
type CloudAssetDetails struct {
	PrivateIPAddresses []string
	PublicIPAddresses  []string
	Hostnames          []string
	ResourceType       string
	AccountID          string
	Region             string
	ResourceID         string
	Tags               map[string]string
}

// NexposeAttributedAssetVulnerabilities is a NexposeAssetVulnerabilities instance combined
// with the business context pertaining to the asset at scan time.
type NexposeAttributedAssetVulnerabilities struct {
	Asset           nexpose.Asset                       `json:"asset"`
	Vulnerabilities []nexpose.AssetVulnerabilityDetails `json:"assetVulnerabilityDetails"`
	BusinessContext *CloudAssetDetails                  `json:"businessContext"`
}
