package v1

import (
	"context"

	"github.com/asecurityteam/nexpose-asset-attributor/pkg/assetattributor"
	"github.com/asecurityteam/nexpose-asset-attributor/pkg/domain"
	"github.com/asecurityteam/nexpose-asset-attributor/pkg/logs"
)

// AttributeHandler handles the Attribution endpoint for nexpose-asset-attributor
type AttributeHandler struct {
	AssetAttributor domain.AssetAttributor
	LogFn           domain.LogFn
	StatFn          domain.StatFn
}

// Handle processes the incoming domain.NexposeAssetVulnerabilities instance, queries available asset inventory systems via its
// AssetAttributor, and returns a domain.AttributedAssetVulnerabilities instance, annotated with the business context of the asset
// at Nexpose scan time.
func (h *AttributeHandler) Handle(ctx context.Context, assetVulns domain.NexposeAssetVulnerabilities) (domain.NexposeAttributedAssetVulnerabilities, error) {
	logger := h.LogFn(ctx)
	stater := h.StatFn(ctx)

	attributedAssetVulns, err := h.AssetAttributor.Attribute(ctx, assetVulns)
	if err != nil {
		switch err.(type) {
		case *assetattributor.AssetNotFoundError:
			logger.Error(logs.AssetNotFoundError{Reason: err.Error()})
			stater.Count("event.nexposeassetattributor.attribution_failure.asset_not_found", 1)
			return domain.NexposeAttributedAssetVulnerabilities{}, err
		case *assetattributor.AssetInventoryRequestError:
			logger.Error(logs.AssetInventoryRequestError{Reason: err.Error()})
			stater.Count("event.nexposeassetattributor.attribution_failure.asset_inventory_request_error", 1)
			return domain.NexposeAttributedAssetVulnerabilities{}, err
		default:
			logger.Error(logs.UnknownAttributionFailureError{Reason: err.Error()})
			stater.Count("event.nexposeassetattributor.attribution_failure.unknown_attribution_failure", 1)
			return domain.NexposeAttributedAssetVulnerabilities{}, err
		}
	}
	return attributedAssetVulns, nil
}
