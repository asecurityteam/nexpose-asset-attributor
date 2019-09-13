package v1

import (
	"context"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"

	"github.com/asecurityteam/nexpose-asset-attributor/pkg/domain"
)

func TestHandle(t *testing.T) {
	input := domain.NexposeAssetVulnerabilities{
		ID: 123,
		Vulnerabilities: []domain.AssetVulnerabilityDetails{
			{ID: "1"},
		},
	}

	tc := []struct {
		name                          string
		output                        domain.NexposeAttributedAssetVulnerabilities
		err                           error
		attributeOK                   bool
		AttributionFailureHandlerFunc func(*MockAttributionFailureHandler)
	}{
		{
			name: "success",
			output: domain.NexposeAttributedAssetVulnerabilities{
				NexposeAssetVulnerabilities: input,
				BusinessContext: domain.CloudAssetDetails{
					Hostnames: []string{"123"},
				},
			},
			err:         nil,
			attributeOK: true,
			AttributionFailureHandlerFunc: func(mockAttributionFailureHandler *MockAttributionFailureHandler) {
			},
		},
		{
			name:        "asset not found error",
			output:      domain.NexposeAttributedAssetVulnerabilities{},
			err:         domain.AssetNotFoundError{},
			attributeOK: false,
			AttributionFailureHandlerFunc: func(mockAttributionFailureHandler *MockAttributionFailureHandler) {
				mockAttributionFailureHandler.EXPECT().HandleAttributionFailure(gomock.Any(), gomock.Any()).Return(nil)
			},
		},
		{
			name:        "asset inventory request error",
			output:      domain.NexposeAttributedAssetVulnerabilities{},
			err:         domain.AssetInventoryRequestError{},
			attributeOK: false,
			AttributionFailureHandlerFunc: func(mockAttributionFailureHandler *MockAttributionFailureHandler) {
			},
		},
		{
			name:        "asset inventory multiple assets found error",
			output:      domain.NexposeAttributedAssetVulnerabilities{},
			err:         domain.AssetInventoryMultipleAssetsFoundError{},
			attributeOK: false,
			AttributionFailureHandlerFunc: func(mockAttributionFailureHandler *MockAttributionFailureHandler) {
				mockAttributionFailureHandler.EXPECT().HandleAttributionFailure(gomock.Any(), gomock.Any()).Return(nil)
			},
		},
		{
			name:        "unknown attribution failure error",
			output:      domain.NexposeAttributedAssetVulnerabilities{},
			err:         errors.New("oh noes"),
			attributeOK: false,
			AttributionFailureHandlerFunc: func(mockAttributionFailureHandler *MockAttributionFailureHandler) {
			},
		},
	}

	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockAttributor := NewMockAssetAttributor(ctrl)
			mockAttributor.EXPECT().Attribute(gomock.Any(), gomock.Any()).Return(tt.output, tt.err)
			mockProducer := NewMockProducer(ctrl)
			if tt.attributeOK {
				mockProducer.EXPECT().Produce(gomock.Any(), tt.output).Return(nil, nil)
			}
			mockAttributionFailureHandler := NewMockAttributionFailureHandler(ctrl)
			tt.AttributionFailureHandlerFunc(mockAttributionFailureHandler)
			handler := &AttributeHandler{
				LogFn:                     testLogFn,
				StatFn:                    testStatFn,
				AssetAttributor:           mockAttributor,
				Producer:                  mockProducer,
				AttributionFailureHandler: mockAttributionFailureHandler,
			}
			err := handler.Handle(context.Background(), input)
			require.IsType(t, tt.err, err)
		})
	}
}
