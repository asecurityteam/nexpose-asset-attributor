package assetvalidator

import (
	"context"
	"errors"

	"github.com/asecurityteam/nexpose-asset-attributor/pkg/domain"
)

// NoopAttributedAssetValidator is a noop implementation of AssetValidator
type NoopAttributedAssetValidator struct {
}

// Validate is a noop implementation, this validator will need to do something, and that is something that
// varies company to company. For testing purposes, this will not throw an error
func (*NoopAttributedAssetValidator) Validate(ctx context.Context, attributedAsset domain.NexposeAttributedAssetVulnerabilities) error {
	return nil
}

// NoopErrorAttributedAssetValidator is a noop implementation of AssetValidator
type NoopErrorAttributedAssetValidator struct {
}

// Validate is a noop implementation, this validator will need to do something, and that is something that
// varies company to company. For testing purposes, this will always throw an error
func (*NoopErrorAttributedAssetValidator) Validate(ctx context.Context, attributedAsset domain.NexposeAttributedAssetVulnerabilities) error {
	return errors.New("this will always throw an error")
}

// FailureValidator is a noop implementation of AssetValidator
type FailureValidator struct {
}

// Validate is a noop implementation, this validator will need to do something, and that is something that
// varies company to company. For testing purposes, this will throw a validation failure error
func (*FailureValidator) Validate(ctx context.Context, attributedAsset domain.NexposeAttributedAssetVulnerabilities) error {
	return ValidationFailure{}
}
