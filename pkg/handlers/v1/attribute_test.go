package v1

import (
	"context"
	"errors"
	"io/ioutil"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/asecurityteam/logevent"
	"github.com/asecurityteam/nexpose-asset-attributor/pkg/assetattributor"
	"github.com/asecurityteam/nexpose-asset-attributor/pkg/domain"
	"github.com/asecurityteam/runhttp"
)

func newNoOpLogger(_ context.Context) runhttp.Logger {
	return logevent.New(logevent.Config{Output: ioutil.Discard})
}

func TestSuccess(t *testing.T) {
	input := domain.NexposeAssetVulnerabilities{
		Asset: domain.Asset{
			ID: 123,
		},
	}

	handler := &AttributeHandler{
		AssetAttributor: assetattributor.NewNoOpAssetAttributor(),
		LogFn:           newNoOpLogger,
		StatFn:          domain.StatFromContext,
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
		Asset: domain.Asset{ID: 123},
	}

	handler := &AttributeHandler{
		AssetAttributor: mockAttributor,
		LogFn:           newNoOpLogger,
		StatFn:          domain.StatFromContext,
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
		Asset: domain.Asset{
			ID: 123,
		},
	}

	handler := &AttributeHandler{
		AssetAttributor: mockAttributor,
		LogFn:           newNoOpLogger,
		StatFn:          domain.StatFromContext,
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
		Asset: domain.Asset{
			ID: 123,
		},
	}

	handler := &AttributeHandler{
		AssetAttributor: mockAttributor,
		LogFn:           newNoOpLogger,
		StatFn:          domain.StatFromContext,
	}
	_, err := handler.Handle(context.Background(), input)
	assert.NotNil(t, err)
}
