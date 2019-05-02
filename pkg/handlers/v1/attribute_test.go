package v1

import (
	"context"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/asecurityteam/nexpose-asset-attributor/pkg/assetattributor"
	"github.com/asecurityteam/nexpose-asset-attributor/pkg/domain"
)

func TestSuccess(t *testing.T) {
	input := domain.NexposeAssetVulnerabilities{
		ID: 123,
	}

	handler := &AttributeHandler{
		AssetAttributor: assetattributor.NewNoOpAssetAttributor(),
		LogFn:           testLogFn,
		StatFn:          testStatFn,
	}
	_, err := handler.Handle(context.Background(), input)
	assert.Nil(t, err, "Got unexpected Error: *v", err)
}

func TestAssetNotFoundError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockAttributor := NewMockAssetAttributor(ctrl)
	mockAttributor.EXPECT().Attribute(gomock.Any(), gomock.Any()).Return(
		domain.NexposeAttributedAssetVulnerabilities{}, &assetattributor.AssetNotFoundError{
			AssetID:        "123",
			AssetInventory: "test",
		})

	input := domain.NexposeAssetVulnerabilities{
		ID: 123,
	}

	handler := &AttributeHandler{
		AssetAttributor: mockAttributor,
		LogFn:           testLogFn,
		StatFn:          testStatFn,
	}
	_, err := handler.Handle(context.Background(), input)
	assert.IsType(t, &assetattributor.AssetNotFoundError{}, err)
}

func TestAssetInventoryRequestError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockAttributor := NewMockAssetAttributor(ctrl)
	mockAttributor.EXPECT().Attribute(gomock.Any(), gomock.Any()).Return(
		domain.NexposeAttributedAssetVulnerabilities{}, &assetattributor.AssetInventoryRequestError{
			AssetID:        "123",
			AssetInventory: "test",
			Code:           503,
		})

	input := domain.NexposeAssetVulnerabilities{
		ID: 123,
	}

	handler := &AttributeHandler{
		AssetAttributor: mockAttributor,
		LogFn:           testLogFn,
		StatFn:          testStatFn,
	}
	_, err := handler.Handle(context.Background(), input)
	assert.IsType(t, &assetattributor.AssetInventoryRequestError{}, err)
}

func TestUnexpectedAttributionFailure(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockAttributor := NewMockAssetAttributor(ctrl)
	mockAttributor.EXPECT().Attribute(gomock.Any(), gomock.Any()).Return(
		domain.NexposeAttributedAssetVulnerabilities{}, errors.New("oh noes"))

	input := domain.NexposeAssetVulnerabilities{
		ID: 123,
	}

	handler := &AttributeHandler{
		AssetAttributor: mockAttributor,
		LogFn:           testLogFn,
		StatFn:          testStatFn,
	}
	_, err := handler.Handle(context.Background(), input)
	assert.NotNil(t, err)
}
