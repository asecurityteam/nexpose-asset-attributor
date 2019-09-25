package assetvalidator

import (
	"context"
	"errors"

	"github.com/asecurityteam/nexpose-asset-attributor/pkg/domain"
)

// NoopAttributtedAssetValidator is a noop implementation of AssetValidator
type NoopAttributtedAssetValidator struct {
}

// Validate is a noop implementation, this validator will need to do something, and that is something that
// varies company to company. For testing purposes, this will not throw an error
func (*NoopAttributtedAssetValidator) Validate(ctx context.Context, attributedAsset domain.NexposeAttributedAssetVulnerabilities) error {
	return nil
}

// NoopErrorAttributtedAssetValidator is a noop implementation of AssetValidator
type NoopErrorAttributtedAssetValidator struct {
}

// Validate is a noop implementation, this validator will need to do something, and that is something that
// varies company to company. For testing purposes, this will always throw an error
func (*NoopErrorAttributtedAssetValidator) Validate(ctx context.Context, attributedAsset domain.NexposeAttributedAssetVulnerabilities) error {
	return errors.New("this will always throw an error")
}
