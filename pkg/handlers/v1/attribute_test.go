package v1

import (
	"context"
	"io/ioutil"
	"testing"

	"github.com/asecurityteam/nexpose-asset-attributor/pkg/assetattributor"
	"github.com/asecurityteam/nexpose-asset-attributor/pkg/domain"
	"github.com/asecurityteam/nexpose-asset-attributor/pkg/nexpose"
	"github.com/asecurityteam/runhttp"
	"github.com/golang/mock/gomock"

	"github.com/asecurityteam/logevent"
)

func TestSuccess(t *testing.T) {
	input := domain.NexposeAssetVulnerabilities{
		Asset: &nexpose.Asset{
			ID: 123,
		},
	}

	handler := &AttributeHandler{
		AssetAttributor: assetattributor.NewNoOpAssetAttributor(),
		LogFn:           runhttp.LoggerFromContext,
		StatFn:          runhttp.StatFromContext,
	}
	ctx := logevent.NewContext(context.Background(), logevent.New(logevent.Config{Output: ioutil.Discard}))
	_, err := handler.Handle(ctx, input)
	if err != nil {
		t.Fatalf("Got unexpected error: %v.", err.Error())
	}
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
		Asset: &nexpose.Asset{
			ID: 123,
		},
	}

	handler := &AttributeHandler{
		AssetAttributor: mockAttributor,
		LogFn:           runhttp.LoggerFromContext,
		StatFn:          runhttp.StatFromContext,
	}
	ctx := logevent.NewContext(context.Background(), logevent.New(logevent.Config{Output: ioutil.Discard}))
	_, err := handler.Handle(ctx, input)
	if _, ok := err.(*assetattributor.AssetNotFoundError); !ok {
		t.Fatalf("Got unexpected error: %v.", err)
	}
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
		Asset: &nexpose.Asset{
			ID: 123,
		},
	}

	handler := &AttributeHandler{
		AssetAttributor: mockAttributor,
		LogFn:           runhttp.LoggerFromContext,
		StatFn:          runhttp.StatFromContext,
	}
	ctx := logevent.NewContext(context.Background(), logevent.New(logevent.Config{Output: ioutil.Discard}))
	_, err := handler.Handle(ctx, input)
	if _, ok := err.(*assetattributor.AssetInventoryRequestError); !ok {
		t.Fatalf("Got unexpected error: %v.", err)
	}
}
