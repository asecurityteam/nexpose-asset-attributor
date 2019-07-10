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
		name        string
		output      domain.NexposeAttributedAssetVulnerabilities
		err         error
		attributeOK bool
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
		},
		{
			name:        "asset not found error",
			output:      domain.NexposeAttributedAssetVulnerabilities{},
			err:         domain.AssetNotFoundError{},
			attributeOK: false,
		},
		{
			name:        "asset inventory request error",
			output:      domain.NexposeAttributedAssetVulnerabilities{},
			err:         domain.AssetInventoryRequestError{},
			attributeOK: false,
		},
		{
			name:        "asset inventory multiple assets found error",
			output:      domain.NexposeAttributedAssetVulnerabilities{},
			err:         domain.AssetInventoryMultipleAssetsFoundError{},
			attributeOK: false,
		},
		{
			name:        "unknown attribution failure error",
			output:      domain.NexposeAttributedAssetVulnerabilities{},
			err:         errors.New("oh noes"),
			attributeOK: false,
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

			handler := &AttributeHandler{
				LogFn:           testLogFn,
				StatFn:          testStatFn,
				AssetAttributor: mockAttributor,
				Producer:        mockProducer,
			}
			err := handler.Handle(context.Background(), input)
			require.IsType(t, tt.err, err)
		})
	}
}
