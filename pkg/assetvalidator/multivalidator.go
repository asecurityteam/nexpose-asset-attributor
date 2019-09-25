package assetvalidator

import (
	"context"
	"fmt"

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
	succeededValidators := make(chan string, len(v.validators))
	failedValidators := make(chan error, len(v.validators))

	for _, validationMethod := range v.validators {
		go func(validator domain.AssetValidator, ctx context.Context, attributedAsset domain.NexposeAttributedAssetVulnerabilities) {
			err := validator.Validate(ctx, attributedAsset)
			if err != nil {
				failedValidators <- err
				return
			}
			succeededValidators <- "success!"
		}(validationMethod, ctx, attributedAsset)
	}

	var errorList []error

	for range v.validators {
		select {
		// TODO: what should i even do in this case, do i need this channel?
		case <-succeededValidators:
			fmt.Println("fuck yea it works")
		case err := <-failedValidators:
			errorList = append(errorList, err)
		}
	}
	if len(errorList) != 0 {
		return MultiValidatorError{ErrorList: errorList}
	}
	// Do the channels need to be closed?

	return nil
}
