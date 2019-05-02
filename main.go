package main

import (
	"context"
	"net/http"
	"os"

	"github.com/aws/aws-lambda-go/lambda"

	"github.com/asecurityteam/nexpose-asset-attributor/pkg/assetattributor"
	"github.com/asecurityteam/nexpose-asset-attributor/pkg/domain"
	v1 "github.com/asecurityteam/nexpose-asset-attributor/pkg/handlers/v1"
	serverfull "github.com/asecurityteam/serverfull/pkg"
	serverfulldomain "github.com/asecurityteam/serverfull/pkg/domain"
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
	handlers := map[string]serverfulldomain.Handler{
		"attribute": lambda.NewHandler(attributeHandler.Handle),
	}
	rt, err := serverfull.NewStatic(ctx, source, handlers)
	if err != nil {
		panic(err.Error())
	}
	if err := rt.Run(); err != nil {
		panic(err.Error())
	}
}
