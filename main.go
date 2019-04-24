package main

import (
	"context"
	"os"

	"github.com/aws/aws-lambda-go/lambda"

	"github.com/asecurityteam/nexpose-asset-attributor/pkg/assetattributor"
	"github.com/asecurityteam/nexpose-asset-attributor/pkg/domain"
	"github.com/asecurityteam/nexpose-asset-attributor/pkg/handlers/v1"
	serverfull "github.com/asecurityteam/serverfull/pkg"
	serverfulldomain "github.com/asecurityteam/serverfull/pkg/domain"
	"github.com/asecurityteam/settings"
)

func main() {
	ctx := context.Background()
	attributeHandler := &v1.AttributeHandler{
		AssetAttributor: assetattributor.NewNoOpAssetAttributor(),
		LogFn:           domain.LoggerFromContext,
		StatFn:          domain.StatFromContext,
	}
	handlers := map[string]serverfulldomain.Handler{
		"attribute": lambda.NewHandler(attributeHandler.Handle),
	}

	source, err := settings.NewEnvSource(os.Environ())
	if err != nil {
		panic(err.Error())
	}
	rt, err := serverfull.NewStatic(ctx, source, handlers)
	if err != nil {
		panic(err.Error())
	}
	if err := rt.Run(); err != nil {
		panic(err.Error())
	}
}
