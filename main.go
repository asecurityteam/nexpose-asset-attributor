package main

import (
	"context"
	"net/http"
	"os"

	"github.com/asecurityteam/nexpose-asset-attributor/pkg/assetattributor"
	"github.com/asecurityteam/nexpose-asset-attributor/pkg/domain"
	v1 "github.com/asecurityteam/nexpose-asset-attributor/pkg/handlers/v1"
	"github.com/asecurityteam/serverfull"
	"github.com/asecurityteam/settings"
)

func main() {
	ctx := context.Background()
	source, err := settings.NewEnvSource(os.Environ())
	if err != nil {
		panic(err.Error())
	}
	assetInventoryAPIAttributorComponent := &assetattributor.AssetInventoryAPIAttributorComponent{}
	assetInventoryAPIAttributor := new(assetattributor.AssetInventoryAPIAttributor)
	if err = settings.NewComponent(ctx, source, assetInventoryAPIAttributorComponent, assetInventoryAPIAttributor); err != nil {
		panic(err.Error())
	}
	assetInventoryAPIAttributor.Client = http.DefaultClient

	attributeHandler := &v1.AttributeHandler{
		AssetAttributor: assetInventoryAPIAttributor,
		LogFn:           domain.LoggerFromContext,
		StatFn:          domain.StatFromContext,
	}
	handlers := map[string]serverfull.Function{
		"attribute": serverfull.NewFunction(attributeHandler.Handle),
	}
	fetcher := &serverfull.StaticFetcher{Functions: handlers}
	if err := serverfull.Start(ctx, source, fetcher); err != nil {
		panic(err.Error())
	}
}
