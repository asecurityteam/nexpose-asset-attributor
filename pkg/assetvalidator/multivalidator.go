package assetvalidator

import (
	"context"
	"fmt"

	"github.com/asecurityteam/nexpose-asset-attributor/pkg/domain"
)

// MultiValidationError represents a collection of errors
// returned by any of the individual AssetValidator implementations
// used by the MultiValidator.
type multiValidationError struct {
	Errors []error
}

func (err multiValidationError) Error() string {
	return fmt.Sprintf("errors: %v", err.Errors)
}

// MultiValidationFailure represents a collection of validation failures
// returned by any of the individual AssetValidator implementations
// used by the MultiValidator.
type multiValidationFailure struct {
	Failures []error
}

func (failure multiValidationFailure) Error() string {
	return fmt.Sprintf("failures: %v", failure.Failures)
}

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
			return domain.ValidationFailure{
				AssetID:     fmt.Sprintf("%d", attributedAsset.NexposeAssetVulnerabilities.ID),
				FailedCheck: "multiple-validation-failures",
				Inner:       multiValidationFailure{Failures: failuresAndErrorsList},
			}
		}
		// there are no such "failures" in failuresAndErrorsList, only contains "errors"
		return domain.ValidationError{
			AssetID:     fmt.Sprintf("%d", attributedAsset.NexposeAssetVulnerabilities.ID),
			FailedCheck: "multiple-validation-errors",
			Inner:       multiValidationError{Errors: failuresAndErrorsList},
		}
	}

	return nil
}
