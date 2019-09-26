package domain

import "context"

// AssetValidator is an interface that arbitrarily validates an attributed asset. This validator
// could vary from company to company, for instance one could check for a specific email schema,
// or whether an asset has all "attributes" completely filled
type AssetValidator interface {
	Validate(ctx context.Context, attributedAsset NexposeAttributedAssetVulnerabilities) error
}
