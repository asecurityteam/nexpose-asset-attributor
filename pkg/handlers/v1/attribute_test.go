package v1

import (
	"context"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/asecurityteam/nexpose-asset-attributor/pkg/domain"
)

func TestHandle(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockAttributor := NewMockAssetAttributor(ctrl)

	input := domain.NexposeAssetVulnerabilities{
		ID: 123,
		Vulnerabilities: []domain.AssetVulnerabilityDetails{
			{ID: "1"},
		},
	}

	tc := []struct {
		name        string
		input       domain.NexposeAssetVulnerabilities
		output      domain.NexposeAttributedAssetVulnerabilities
		errExpected bool
		err         error
	}{
		{
			name:  "success",
			input: input,
			output: domain.NexposeAttributedAssetVulnerabilities{
				NexposeAssetVulnerabilities: input,
				BusinessContext: domain.CloudAssetDetails{
					Hostnames: []string{"123"},
				},
			},
			errExpected: false,
			err:         nil,
		},
		{
			name:        "asset not found error",
			input:       input,
			output:      domain.NexposeAttributedAssetVulnerabilities{},
			errExpected: true,
			err:         domain.AssetNotFoundError{},
		},
		{
			name:        "asset inventory request error",
			input:       input,
			output:      domain.NexposeAttributedAssetVulnerabilities{},
			errExpected: true,
			err:         domain.AssetInventoryRequestError{},
		},
		{
			name:        "asset inventory multiple assets found error",
			input:       input,
			output:      domain.NexposeAttributedAssetVulnerabilities{},
			errExpected: true,
			err:         domain.AssetInventoryMultipleAssetsFoundError{},
		},
		{
			name:        "unknown attribution failure error",
			input:       input,
			output:      domain.NexposeAttributedAssetVulnerabilities{},
			errExpected: true,
			err:         errors.New("oh noes"),
		},
	}

	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			handler := &AttributeHandler{
				AssetAttributor: mockAttributor,
				LogFn:           testLogFn,
				StatFn:          testStatFn,
			}
			mockAttributor.EXPECT().Attribute(gomock.Any(), gomock.Any()).Return(
				tt.output, tt.err)
			actual, err := handler.Handle(context.Background(), tt.input)
			if tt.errExpected {
				require.IsType(t, tt.err, err)
			} else {
				assert.Nil(t, err, "Got unexpected Error: *v", err)
			}
			assert.Equal(t, tt.output, actual)
		})
	}
}
