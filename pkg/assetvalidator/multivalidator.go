package assetvalidator

import (
	"context"

	"github.com/asecurityteam/nexpose-asset-attributor/pkg/domain"
)

// MultiAttributedAssetValidator is an implementation of AssetValidator which runs specified multiple validations
// of type AssetValidator. In the event that a company needs different validation checks for an attributed asset, this implementation
// will handle that
type MultiAttributedAssetValidator struct {
	Validators []domain.AssetValidator
}

// Validate is an implementation that will run multiple validations in a fan out pattern.
// If any validator fails, then the entire multi validation fails
func (v *MultiAttributedAssetValidator) Validate(ctx context.Context, attributedAsset domain.NexposeAttributedAssetVulnerabilities) error {

	validationResults := make(chan error, len(v.Validators))

	for _, validationMethod := range v.Validators {
		go func(validator domain.AssetValidator, ctx context.Context, attributedAsset domain.NexposeAttributedAssetVulnerabilities) {
			// send back nil or error from Validate, will check results later
			validationResults <- validator.Validate(ctx, attributedAsset)
		}(validationMethod, ctx, attributedAsset)
	}

	var errorList []error

	for range v.Validators {
		err := <-validationResults
		if err != nil {
			errorList = append(errorList, err)
		}
	}
	if len(errorList) > 0 {
		var failureList []error
		for _, err := range errorList {
			switch err.(type) {
			case ValidationFailure:
				failureList = append(failureList, err)
			default:
				continue
			}
		}
		if len(failureList) > 0 {
			return ValidationFailure{FailureList: failureList}
		}
		return MultiValidatorError{ErrorList: errorList}
	}

	return nil
}
