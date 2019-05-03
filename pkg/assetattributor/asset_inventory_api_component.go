package assetattributor

import (
	"context"
)

// AssetInventoryAPIAttributorConfig defines the configuration options for a AssetInventoryAPIAttributor.
type AssetInventoryAPIAttributorConfig struct {
	Host           string `description:"The hostname of the asset-inventory-api service to query."`
	CloudAssetPath string `description:"The cloud asset URI path for asset-inventory-api"`
}

// Name is used by the settings library to replace the default naming convention.
func (c *AssetInventoryAPIAttributorConfig) Name() string {
	return "assetinventoryapiattributor"
}

// AssetInventoryAPIAttributorComponent satisfies the settings library Component API,
// and may be used by the settings.NewComponent function.
type AssetInventoryAPIAttributorComponent struct{}

// Settings populates a set of default valid resource types for the ResourceTypeFilterer
// if none are provided via config.
func (*AssetInventoryAPIAttributorComponent) Settings() *AssetInventoryAPIAttributorConfig {
	return &AssetInventoryAPIAttributorConfig{}
}

// New constructs a ResourceTypeFilterer from a config.
func (*AssetInventoryAPIAttributorComponent) New(_ context.Context, c *AssetInventoryAPIAttributorConfig) (*AssetInventoryAPIAttributor, error) {
	return &AssetInventoryAPIAttributor{
		Host:           c.Host,
		CloudAssetPath: c.CloudAssetPath,
	}, nil
}
