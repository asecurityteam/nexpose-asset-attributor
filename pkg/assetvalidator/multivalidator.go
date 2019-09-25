package assetvalidator

import (
	"context"

	"github.com/asecurityteam/nexpose-asset-attributor/pkg/domain"
)

// MultiAttributtedAssetValidator is an implementation of AssetValidator which runs specified multiple validations
// of type AssetValidator. In the event that a company needs different validation checks for an attributed asset, this implementation
// will handle that
type MultiAttributtedAssetValidator struct {
	validators []domain.AssetValidator
}

// Validate is a noop implementation, this validator will need to do something, and that is something that
// varies company to company
func (v *MultiAttributtedAssetValidator) Validate(ctx context.Context, attributedAsset domain.NexposeAttributedAssetVulnerabilities) error {

	validationResults := make(chan error, len(v.validators))

	for _, validationMethod := range v.validators {
		go func(validator domain.AssetValidator, ctx context.Context, attributedAsset domain.NexposeAttributedAssetVulnerabilities) {
			err := validator.Validate(ctx, attributedAsset)
			if err != nil {
				validationResults <- err
				return
			}
			validationResults <- nil
		}(validationMethod, ctx, attributedAsset)
	}

	var errorList []error

	for range v.validators {
		err := <-validationResults
		if err != nil {
			errorList = append(errorList, err)
		}
	}
	if len(errorList) > 0 {
		return MultiValidatorError{ErrorList: errorList}
	}
	// Do the channels need to be closed?

	return nil
}
