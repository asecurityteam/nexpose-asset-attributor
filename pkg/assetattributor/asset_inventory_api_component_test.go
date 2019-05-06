package assetattributor

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAssetInventoryAPIAttributorComponentNew(t *testing.T) {
	tc := []struct {
		name string
		host string
		err  error
	}{
		{
			name: "valid host",
			host: "https://localhost:8080",
			err:  nil,
		},
		{
			name: "invalid host",
			host: "~!@#$%^&*()_+:?><!@#$%^&*())_:",
			err:  fmt.Errorf("bad"),
		},
	}

	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			config := &AssetInventoryAPIAttributorConfig{
				Host: tt.host,
			}
			component := &AssetInventoryAPIAttributorComponent{}
			_, err := component.New(context.Background(), config)
			if tt.err != nil {
				require.Error(t, err)
				return
			}
			require.Nil(t, err)
		})
	}
}
