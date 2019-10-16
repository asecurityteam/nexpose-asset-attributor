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

	var failuresAndErrorsList []error

	// loop through results of every validator. Note that validationResults channel
	// contains type error, but type error is classified as a "failure" or an "error"(failed unexpectantly)
	for range v.Validators {
		err := <-validationResults
		if err != nil {
			failuresAndErrorsList = append(failuresAndErrorsList, err)
		}
	}
	if len(failuresAndErrorsList) > 0 {
		var failureList []error
		for _, err := range failuresAndErrorsList {
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
		// there are no such "failures" in failuresAndErrorsList, only contains "errors"
		return ValidationError{ErrorList: failuresAndErrorsList}
	}

	return nil
}
