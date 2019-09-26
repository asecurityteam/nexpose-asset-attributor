package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	producer "github.com/asecurityteam/component-producer"
	"github.com/asecurityteam/nexpose-asset-attributor/pkg/assetattributionfailure"
	"github.com/asecurityteam/nexpose-asset-attributor/pkg/assetattributor"
	"github.com/asecurityteam/nexpose-asset-attributor/pkg/assetvalidator"
	"github.com/asecurityteam/nexpose-asset-attributor/pkg/domain"
	v1 "github.com/asecurityteam/nexpose-asset-attributor/pkg/handlers/v1"
	"github.com/asecurityteam/serverfull"
	"github.com/asecurityteam/settings"
)

type config struct {
	Producer            *producer.Config
	CloudAssetInventory *assetattributor.CloudAssetInventoryConfig
	LambdaMode          bool `description:"Use the Lambda SDK to start the system."`
}

func (*config) Name() string {
	return "nexposeassetattributor"
}

type component struct {
	Producer            *producer.Component
	CloudAssetInventory *assetattributor.CloudAssetInventoryComponent
}

func newComponent() *component {
	return &component{
		Producer:            producer.NewComponent(),
		CloudAssetInventory: assetattributor.NewCloudAssetInventoryComponent(),
	}
}

func (c *component) Settings() *config {
	return &config{
		Producer:            c.Producer.Settings(),
		CloudAssetInventory: c.CloudAssetInventory.Settings(),
	}
}

func (c *component) New(ctx context.Context, conf *config) (func(context.Context, settings.Source) error, error) {
	a, err := c.CloudAssetInventory.New(ctx, conf.CloudAssetInventory)
	if err != nil {
		return nil, err
	}
	p, err := c.Producer.New(ctx, conf.Producer)
	if err != nil {
		return nil, err
	}

	attributeHandler := &v1.AttributeHandler{
		LogFn:           domain.LoggerFromContext,
		StatFn:          domain.StatFromContext,
		AssetAttributor: a,
		// AttributionFailureHandler and AttributedAssetValidator fields are stubs, as the actual implementations
		// of these interfaces will likely vary greatly among different operators of this service.
		AttributionFailureHandler: &assetattributionfailure.NoopAttributionFailureHandler{},
		AttributedAssetValidator:  &assetvalidator.NoopAttributedAssetValidator{},
		Producer:                  p,
	}
	handlers := map[string]serverfull.Function{
		"attribute": serverfull.NewFunction(attributeHandler.Handle),
	}
	fetcher := &serverfull.StaticFetcher{Functions: handlers}
	if conf.LambdaMode {
		return func(ctx context.Context, source settings.Source) error {
			return serverfull.StartLambda(ctx, source, fetcher, "attribute")
		}, nil
	}
	return func(ctx context.Context, source settings.Source) error {
		return serverfull.StartHTTP(ctx, source, fetcher)
	}, nil
}

func main() {
	source, err := settings.NewEnvSource(os.Environ())
	if err != nil {
		panic(err.Error())
	}
	ctx := context.Background()
	runner := new(func(context.Context, settings.Source) error)
	cmp := newComponent()

	// Print names and example values for all defined environment variables
	// when -h or -help are passed as flags.
	fs := flag.NewFlagSet("nexpose-asset-attributor", flag.ContinueOnError)
	fs.Usage = func() {}
	if err = fs.Parse(os.Args[1:]); err == flag.ErrHelp {
		g, _ := settings.GroupFromComponent(cmp)
		fmt.Println("Usage: ")
		fmt.Println(settings.ExampleEnvGroups([]settings.Group{g}))
		return
	}

	err = settings.NewComponent(ctx, source, cmp, runner)
	if err != nil {
		panic(err.Error())
	}
	if err := (*runner)(ctx, source); err != nil {
		panic(err.Error())
	}
}
