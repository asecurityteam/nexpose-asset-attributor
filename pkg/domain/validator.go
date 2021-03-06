package domain

import (
	"context"
	"fmt"
)

// AssetValidator could vary from company to company, for instance one could check for a specific email schema,
// or whether an asset has all "attributes" completely filled
type AssetValidator interface {

	// AssetValidator is an interface that arbitrarily validates an attributed asset.
	Validate(ctx context.Context, attributedAsset NexposeAttributedAssetVulnerabilities) error
}

// ValidationError occurs when the process of validation fails
// unexpectedly, and not due to an invalid attributed asset
// Examples of usage would include a bad http call
type ValidationError struct {
	FailedCheck string
	Inner       error
}

func (err ValidationError) Error() string {
	return fmt.Sprintf("Error occurred during validation %s: %v",
		err.FailedCheck, err.Inner)
}

// ValidationFailure occurs when any validation check fails
// validation, in other words an asset is invalid
type ValidationFailure struct {
	FailedCheck string
	Inner       error
}

func (failure ValidationFailure) Error() string {
	return fmt.Sprintf("Validation %s failed: %v",
		failure.FailedCheck, failure.Inner)
}
