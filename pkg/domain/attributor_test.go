package domain

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCustomUnmarshalling(t *testing.T) {
	b := []byte(`{"id":1,"hostname":"bowser"}`)
	partial := NexposeAttributedAssetVulnerabilities{}
	err := json.Unmarshal(b, &partial)
	require.Nil(t, err)

	expectedNested := NexposeAssetVulnerabilities{
		ID:              1,
		Hostname:        "bowser",
		Vulnerabilities: make([]AssetVulnerabilityDetails, 0),
	}

	expected := NexposeAttributedAssetVulnerabilities{
		NexposeAssetVulnerabilities: expectedNested,
		BusinessContext: CloudAssetDetails{

			PrivateIPAddresses: make([]string, 0),
			PublicIPAddresses:  make([]string, 0),
			Hostnames:          make([]string, 0),
			Tags:               make(map[string]string),
		},
	}

	// kind of a dumb test... but good enough to see
	marshalled, _ := json.Marshal(partial)
	badMarshalMsg := "You've added a new field in the struct hierarchy that is type array, slice, or map, but forgot to add custom unmarshalling logic for it"
	require.False(t, strings.Contains(string(marshalled), "null"), badMarshalMsg)

	fmt.Println(string(marshalled))

	fmt.Println("EXPECTED")
	fmt.Println(expected)
	marshalled2, _ := json.Marshal(expected)
	fmt.Println(string(marshalled2))

	require.True(t, reflect.DeepEqual(expected, partial), "marshalled object does not equal expected object")
}
