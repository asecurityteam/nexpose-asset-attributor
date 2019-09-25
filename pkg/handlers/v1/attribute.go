package v1

import (
	"context"

	"github.com/asecurityteam/nexpose-asset-attributor/pkg/domain"
	"github.com/asecurityteam/nexpose-asset-attributor/pkg/logs"
)

// AttributeHandler handles the Attribution endpoint for nexpose-asset-attributor
type AttributeHandler struct {
	Producer                  domain.Producer
	AssetAttributor           domain.AssetAttributor
	AttributionFailureHandler domain.AttributionFailureHandler // used as a generic handler if an asset has incomplete attributes
	AttributedAssetValidator  domain.AssetValidator
	LogFn                     domain.LogFn
	StatFn                    domain.StatFn
}

// Handle processes the incoming domain.NexposeAssetVulnerabilities instance, queries available asset inventory systems
// via its AssetAttributor, and produces a domain.AttributedAssetVulnerabilities instance to a stream, annotated with
// the business context of the asset at Nexpose scan time.
func (h *AttributeHandler) Handle(ctx context.Context, assetVulns domain.NexposeAssetVulnerabilities) error {
	logger := h.LogFn(ctx)

	attributedAssetVulns, attributionErr := h.AssetAttributor.Attribute(ctx, assetVulns)
	if attributionErr != nil {
		switch attributionErr.(type) {
		case domain.AssetNotFoundError:
			logger.Error(logs.AssetNotFoundError{Reason: attributionErr.Error()})
		case domain.AssetInventoryRequestError:
			logger.Error(logs.AssetInventoryRequestError{Reason: attributionErr.Error()})
		case domain.AssetInventoryMultipleAssetsFoundError:
			logger.Error(logs.AssetInventoryMultipleAssetsFoundError{Reason: attributionErr.Error()})
		default:
			logger.Error(logs.UnknownAttributionFailureError{Reason: attributionErr.Error()})
		}
		err := h.AttributionFailureHandler.HandleAttributionFailure(ctx, domain.NexposeAttributedAssetVulnerabilities{NexposeAssetVulnerabilities: assetVulns})
		if err != nil {
			return err
		}
		return attributionErr
	}

	validationErr := h.AttributedAssetValidator.Validate(ctx, attributedAssetVulns)
	if validationErr != nil {
		logger.Error(logs.AttributedAssetValidationError{Reason: validationErr.Error()})
		err := h.AttributionFailureHandler.HandleAttributionFailure(ctx, attributedAssetVulns)
		if err != nil {
			return err
		}
		return validationErr
	}

	_, err := h.Producer.Produce(ctx, attributedAssetVulns)
	return err
}
