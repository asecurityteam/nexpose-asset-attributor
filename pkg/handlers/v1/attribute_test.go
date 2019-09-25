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
		name                           string
		output                         domain.NexposeAttributedAssetVulnerabilities
		attributedErr                  error
		attributeAndValidateOK         bool
		AttributionFailureHandlerFunc  func(*MockAttributionFailureHandler)
		AttributtedAssetValidationFunc func(*MockAssetValidator)
		result                         error
	}{
		{
			name: "success",
			output: domain.NexposeAttributedAssetVulnerabilities{
				NexposeAssetVulnerabilities: input,
				BusinessContext: domain.CloudAssetDetails{
					Hostnames: []string{"123"},
				},
			},
			attributedErr:          nil,
			attributeAndValidateOK: true,
			AttributionFailureHandlerFunc: func(mockAttributionFailureHandler *MockAttributionFailureHandler) {
			},
			AttributtedAssetValidationFunc: func(mockAssetValidator *MockAssetValidator) {
				mockAssetValidator.EXPECT().Validate(gomock.Any(), gomock.Any()).Return(nil)
			},
			result: nil,
		},
		{
			name:                   "asset not found error",
			output:                 domain.NexposeAttributedAssetVulnerabilities{},
			attributedErr:          domain.AssetNotFoundError{},
			attributeAndValidateOK: false,
			AttributionFailureHandlerFunc: func(mockAttributionFailureHandler *MockAttributionFailureHandler) {
				mockAttributionFailureHandler.EXPECT().HandleAttributionFailure(gomock.Any(), gomock.Any()).Return(nil)
			},
			AttributtedAssetValidationFunc: func(mockAssetValidator *MockAssetValidator) {
			},
			result: domain.AssetNotFoundError{},
		},
		{
			name:                   "asset inventory request error",
			output:                 domain.NexposeAttributedAssetVulnerabilities{},
			attributedErr:          domain.AssetInventoryRequestError{},
			attributeAndValidateOK: false,
			AttributionFailureHandlerFunc: func(mockAttributionFailureHandler *MockAttributionFailureHandler) {
				mockAttributionFailureHandler.EXPECT().HandleAttributionFailure(gomock.Any(), gomock.Any()).Return(nil)
			},
			AttributtedAssetValidationFunc: func(mockAssetValidator *MockAssetValidator) {
			},
			result: domain.AssetInventoryRequestError{},
		},
		{
			name:                   "asset inventory multiple assets found error",
			output:                 domain.NexposeAttributedAssetVulnerabilities{},
			attributedErr:          domain.AssetInventoryMultipleAssetsFoundError{},
			attributeAndValidateOK: false,
			AttributionFailureHandlerFunc: func(mockAttributionFailureHandler *MockAttributionFailureHandler) {
				mockAttributionFailureHandler.EXPECT().HandleAttributionFailure(gomock.Any(), gomock.Any()).Return(nil)
			},
			AttributtedAssetValidationFunc: func(mockAssetValidator *MockAssetValidator) {
			},
			result: domain.AssetInventoryMultipleAssetsFoundError{},
		},
		{
			name:                   "unknown attribution failure error",
			output:                 domain.NexposeAttributedAssetVulnerabilities{},
			attributedErr:          errors.New("oh noes"),
			attributeAndValidateOK: false,
			AttributionFailureHandlerFunc: func(mockAttributionFailureHandler *MockAttributionFailureHandler) {
				mockAttributionFailureHandler.EXPECT().HandleAttributionFailure(gomock.Any(), gomock.Any()).Return(nil)
			},
			AttributtedAssetValidationFunc: func(mockAssetValidator *MockAssetValidator) {
			},
			result: errors.New("oh noes"),
		},
		{
			name: "attributed asset validation failure",
			output: domain.NexposeAttributedAssetVulnerabilities{
				NexposeAssetVulnerabilities: input,
				BusinessContext: domain.CloudAssetDetails{
					Hostnames: []string{"123"},
				},
			},
			attributedErr:          nil,
			attributeAndValidateOK: false,
			AttributionFailureHandlerFunc: func(mockAttributionFailureHandler *MockAttributionFailureHandler) {
				mockAttributionFailureHandler.EXPECT().HandleAttributionFailure(gomock.Any(), gomock.Any()).Return(nil)
			},
			AttributtedAssetValidationFunc: func(mockAssetValidator *MockAssetValidator) {
				mockAssetValidator.EXPECT().Validate(gomock.Any(), gomock.Any()).Return(errors.New("validation error occurred here"))
			},
			result: errors.New("validation error occurred here"),
		},
	}

	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockAttributor := NewMockAssetAttributor(ctrl)
			mockAttributor.EXPECT().Attribute(gomock.Any(), gomock.Any()).Return(tt.output, tt.attributedErr)
			mockProducer := NewMockProducer(ctrl)
			if tt.attributeAndValidateOK {
				mockProducer.EXPECT().Produce(gomock.Any(), tt.output).Return(nil, nil)
			}
			mockAttributionFailureHandler := NewMockAttributionFailureHandler(ctrl)
			mockAssetValidator := NewMockAssetValidator(ctrl)

			tt.AttributionFailureHandlerFunc(mockAttributionFailureHandler)
			tt.AttributtedAssetValidationFunc(mockAssetValidator)
			handler := &AttributeHandler{
				LogFn:                     testLogFn,
				StatFn:                    testStatFn,
				AssetAttributor:           mockAttributor,
				AttributedAssetValidator:  mockAssetValidator,
				Producer:                  mockProducer,
				AttributionFailureHandler: mockAttributionFailureHandler,
			}
			err := handler.Handle(context.Background(), input)
			require.IsType(t, tt.result, err)
		})
	}
}
