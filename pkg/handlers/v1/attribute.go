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
	LogFn                     domain.LogFn
	StatFn                    domain.StatFn
}

// Handle processes the incoming domain.NexposeAssetVulnerabilities instance, queries available asset inventory systems
// via its AssetAttributor, and produces a domain.AttributedAssetVulnerabilities instance to a stream, annotated with
// the business context of the asset at Nexpose scan time.
func (h *AttributeHandler) Handle(ctx context.Context, assetVulns domain.NexposeAssetVulnerabilities) error {
	logger := h.LogFn(ctx)

	attributedAssetVulns, err := h.AssetAttributor.Attribute(ctx, assetVulns)
	if err != nil {
		switch err.(type) {
		case domain.AssetNotFoundError:
			logger.Error(logs.AssetNotFoundError{Reason: err.Error()})
			err = h.AttributionFailureHandler.HandleAttributionFailure(ctx, attributedAssetVulns)
			return err
		case domain.AssetInventoryRequestError:
			logger.Error(logs.AssetInventoryRequestError{Reason: err.Error()})
			return err
		case domain.AssetInventoryMultipleAssetsFoundError:
			logger.Error(logs.AssetInventoryMultipleAssetsFoundError{Reason: err.Error()})
			return err
		default:
			logger.Error(logs.UnknownAttributionFailureError{Reason: err.Error()})
			return err
		}
	}
	_, err = h.Producer.Produce(ctx, attributedAssetVulns)
	return err
}
