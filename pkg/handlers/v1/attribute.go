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
		logger.Error(logs.AttributionErrorLogFactory(attributionErr, assetVulns.ID))
		err := h.AttributionFailureHandler.HandleAttributionFailure(ctx, domain.NexposeAttributedAssetVulnerabilities{NexposeAssetVulnerabilities: assetVulns}, attributionErr)
		if err != nil {
			return err
		}
		return attributionErr
	}

	validationErr := h.AttributedAssetValidator.Validate(ctx, attributedAssetVulns)
	if validationErr != nil {

		logger.Error(logs.ValidationErrorLogFactory(validationErr, assetVulns.ID, attributedAssetVulns.BusinessContext.ARN, attributedAssetVulns.BusinessContext.ResourceType))

		failureHandlerErr := h.AttributionFailureHandler.HandleAttributionFailure(ctx, attributedAssetVulns, validationErr)
		if failureHandlerErr != nil {
			return failureHandlerErr
		}
		return validationErr
	}

	_, producerErr := h.Producer.Produce(ctx, attributedAssetVulns)
	if producerErr != nil {
		failureHandlerErr := h.AttributionFailureHandler.HandleAttributionFailure(ctx, attributedAssetVulns, producerErr)
		if failureHandlerErr != nil {
			return failureHandlerErr
		}
	}

	return producerErr
}
