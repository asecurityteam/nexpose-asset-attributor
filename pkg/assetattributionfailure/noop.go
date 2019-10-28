package assetattributionfailure

import (
	"context"

	"github.com/asecurityteam/nexpose-asset-attributor/pkg/domain"
)

// NoopAttributionFailureHandler is a noop implementation of AttributionFailureHandler
type NoopAttributionFailureHandler struct {
}

// HandleAttributionFailure is a noop implementation
func (*NoopAttributionFailureHandler) HandleAttributionFailure(ctx context.Context, failedAttributedAsset domain.NexposeAttributedAssetVulnerabilities, failure error) error {
	return nil
}
