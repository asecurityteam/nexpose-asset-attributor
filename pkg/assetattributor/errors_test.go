package assetattributor

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEmptyErrors(t *testing.T) {
	tc := []struct {
		name string
		err  error
	}{
		{
			name: "httpNotFound",
			err:  httpNotFound{},
		},
		{
			name: "httpBadRequest",
			err:  httpBadRequest{},
		},
		{
			name: "httpRequestError",
			err:  httpRequestError{},
		},
		{
			name: "httpMultipleAssetsFoundError",
			err:  httpMultipleAssetsFoundError{},
		},
		{
			name: "combinedError",
			err:  combinedError{},
		},
	}

	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			require.NotEmpty(t, tt.err.Error())
		})
	}
}
