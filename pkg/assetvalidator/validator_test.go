package assetvalidator

import (
	"context"
	"testing"

	"github.com/asecurityteam/nexpose-asset-attributor/pkg/domain"
	"github.com/stretchr/testify/assert"
)

func TestMultiValidatorSingleValidatorSuccess(t *testing.T) {
	noopValidator := NoopAttributedAssetValidator{}
	ctx := context.Background()
	multiValidator := MultiAttributedAssetValidator{Validators: []domain.AssetValidator{&noopValidator}}
	attributedAsset := domain.NexposeAttributedAssetVulnerabilities{BusinessContext: domain.CloudAssetDetails{ARN: "valid attribution"}}
	result := multiValidator.Validate(ctx, attributedAsset)
	assert.Equal(t, result, nil)
}

func TestMultiValidatorMultipleValidatorsSuccess(t *testing.T) {
	noopValidator1 := NoopAttributedAssetValidator{}
	noopValidator2 := NoopAttributedAssetValidator{}
	ctx := context.Background()
	multiValidator := MultiAttributedAssetValidator{Validators: []domain.AssetValidator{&noopValidator1, &noopValidator2}}
	attributedAsset := domain.NexposeAttributedAssetVulnerabilities{BusinessContext: domain.CloudAssetDetails{ARN: "valid attribution"}}
	result := multiValidator.Validate(ctx, attributedAsset)
	assert.Equal(t, result, nil)
}

func TestMultiValidatorSingleValidatorError(t *testing.T) {
	noopValidator := NoopErrorAttributedAssetValidator{}
	ctx := context.Background()
	multiValidator := MultiAttributedAssetValidator{Validators: []domain.AssetValidator{&noopValidator}}
	attributedAsset := domain.NexposeAttributedAssetVulnerabilities{BusinessContext: domain.CloudAssetDetails{ARN: "invalid attribution"}}
	result := multiValidator.Validate(ctx, attributedAsset)
	assert.Equal(t, result.Error(), "Error occurred during validation multiple-validation-errors for Asset 0: errors: [Error occurred during validation validation-error for Asset 0: this will always throw an error]")
	assert.IsType(t, domain.ValidationError{}, result)
}

func TestMultiValidatorMultipleValidatorError(t *testing.T) {
	noopValidator1 := NoopAttributedAssetValidator{}
	noopValidator2 := NoopErrorAttributedAssetValidator{}
	noopValidator3 := NoopErrorAttributedAssetValidator{}
	ctx := context.Background()
	multiValidator := MultiAttributedAssetValidator{Validators: []domain.AssetValidator{&noopValidator1, &noopValidator2, &noopValidator3}}
	attributedAsset := domain.NexposeAttributedAssetVulnerabilities{BusinessContext: domain.CloudAssetDetails{ARN: "invalid attribution"}}
	result := multiValidator.Validate(ctx, attributedAsset)
	assert.Equal(t, result.Error(), "Error occurred during validation multiple-validation-errors for Asset 0: errors: [Error occurred during validation validation-error for Asset 0: this will always throw an error Error occurred during validation validation-error for Asset 0: this will always throw an error]")
	assert.IsType(t, domain.ValidationError{}, result)
}

func TestMultiValidatorValidationFailure(t *testing.T) {
	noopValidator1 := NoopAttributedAssetValidator{}
	noopValidator2 := NoopErrorAttributedAssetValidator{}
	noopValidator3 := FailureValidator{}
	ctx := context.Background()
	multiValidator := MultiAttributedAssetValidator{Validators: []domain.AssetValidator{&noopValidator1, &noopValidator2, &noopValidator3}}
	attributedAsset := domain.NexposeAttributedAssetVulnerabilities{BusinessContext: domain.CloudAssetDetails{ARN: "invalid attribution"}}
	result := multiValidator.Validate(ctx, attributedAsset)
	assert.IsType(t, domain.ValidationFailure{}, result)
}
