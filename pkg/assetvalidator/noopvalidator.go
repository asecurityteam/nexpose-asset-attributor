package assetvalidator

import (
	"context"

	"github.com/asecurityteam/nexpose-asset-attributor/pkg/domain"
)

// NoopAttributtedAssetValidator is a noop implementation of AssetValidator
type NoopAttributtedAssetValidator struct {
}

// Validate is a noop implementation, this validator will need to do something, and that is something that
// varies company to company
func (*NoopAttributtedAssetValidator) Validate(ctx context.Context, attributedAsset domain.NexposeAttributedAssetVulnerabilities) error {
	return nil
}
