package assetattributor

import "github.com/asecurityteam/nexpose-asset-attributor/pkg/domain"

// NoOpAssetAttributor is an implementation of AssetAttributor that queries no
// asset inventory systems, but instead returns a zero-value domain.CloudAssetDetails for
// the asset's business context.
type NoOpAssetAttributor struct{}

// NewNoOpAssetAttributor returns a fully configured NoOpAssetAttributor
func NewNoOpAssetAttributor() *NoOpAssetAttributor {
	return &NoOpAssetAttributor{}
}

// Attribute returns a zero-value domain.CloudAssetDetails for the scan-time business context
// of the given domain.NexposeAssetVulnerabilities instance
func (n *NoOpAssetAttributor) Attribute(asset domain.NexposeAssetVulnerabilities) (domain.NexposeAttributedAssetVulnerabilities, error) {
	return domain.NexposeAttributedAssetVulnerabilities{
		Asset:           asset.Asset,
		Vulnerabilities: asset.Vulnerabilities,
		BusinessContext: &domain.CloudAssetDetails{},
	}, nil
}
