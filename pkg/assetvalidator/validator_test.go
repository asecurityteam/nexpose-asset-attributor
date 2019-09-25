package assetvalidator

import (
	"context"
	"testing"

	"github.com/asecurityteam/nexpose-asset-attributor/pkg/domain"
	"github.com/stretchr/testify/assert"
)

func TestMultiValidatorSingleValidatorSuccess(t *testing.T) {
	noopValidator := NoopAttributtedAssetValidator{}
	ctx := context.Background()
	multiValidator := MultiAttributtedAssetValidator{validators: []domain.AssetValidator{&noopValidator}}
	attributedAsset := domain.NexposeAttributedAssetVulnerabilities{BusinessContext: domain.CloudAssetDetails{ARN: "valid attribution"}}
	result := multiValidator.Validate(ctx, attributedAsset)
	assert.Equal(t, result, nil)
}

func TestMultiValidatorMultipleValidatorsSuccess(t *testing.T) {
	noopValidator1 := NoopAttributtedAssetValidator{}
	noopValidator2 := NoopAttributtedAssetValidator{}
	ctx := context.Background()
	multiValidator := MultiAttributtedAssetValidator{validators: []domain.AssetValidator{&noopValidator1, &noopValidator2}}
	attributedAsset := domain.NexposeAttributedAssetVulnerabilities{BusinessContext: domain.CloudAssetDetails{ARN: "valid attribution"}}
	result := multiValidator.Validate(ctx, attributedAsset)
	assert.Equal(t, result, nil)
}

func TestMultiValidatorSingleValidatorError(t *testing.T) {
	noopValidator := NoopErrorAttributtedAssetValidator{}
	ctx := context.Background()
	multiValidator := MultiAttributtedAssetValidator{validators: []domain.AssetValidator{&noopValidator}}
	attributedAsset := domain.NexposeAttributedAssetVulnerabilities{BusinessContext: domain.CloudAssetDetails{ARN: "invalid attribution"}}
	result := multiValidator.Validate(ctx, attributedAsset)
	assert.Equal(t, result.Error(), "\nthis will always throw an error")
}

func TestMultiValidatorMultipleValidatorError(t *testing.T) {
	noopValidator1 := NoopAttributtedAssetValidator{}
	noopValidator2 := NoopErrorAttributtedAssetValidator{}
	noopValidator3 := NoopErrorAttributtedAssetValidator{}
	ctx := context.Background()
	multiValidator := MultiAttributtedAssetValidator{validators: []domain.AssetValidator{&noopValidator1, &noopValidator2, &noopValidator3}}
	attributedAsset := domain.NexposeAttributedAssetVulnerabilities{BusinessContext: domain.CloudAssetDetails{ARN: "invalid attribution"}}
	result := multiValidator.Validate(ctx, attributedAsset)
	assert.Equal(t, result.Error(), "\n\nthis will always throw an error\nthis will always throw an error")
}
