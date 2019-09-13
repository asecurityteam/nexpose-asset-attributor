package v1

import (
	"context"

	"github.com/asecurityteam/nexpose-asset-attributor/pkg/domain"
)

type nopAttributionFailureHandler struct{}

func (*nopAttributionFailureHandler) HandleAttributionFailure(ctx context.Context, failedAttributedAsset domain.NexposeAttributedAssetVulnerabilities) error {
	return nil
}
func mockAttributionFailureHandler() *nopAttributionFailureHandler {
	return &nopAttributionFailureHandler{}
}
