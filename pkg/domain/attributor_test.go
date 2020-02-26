package domain

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCustomUnmarshallingFull(t *testing.T) {

	expectedLastScanned, _ := time.Parse(time.RFC3339Nano, "2019-09-24 18:10:25.19942 -0500 CDT")
	expectedLastScannedString := expectedLastScanned.Format(time.RFC3339Nano)

	b := []byte(fmt.Sprintf(`{"scanTime":"%s","hostname":"bowser","id":1,"ip":"9.8.7.6","assetVulnerabilityDetails":[{"id":"a","results":[{"port":3,"protocol":"udp","proof":"I said it"}],"status":"done","cvssV2Score":42,"cvssV2Severity":"uhh, low","description":"it's bad, you know","title":"title here","solutions":["solution"]}],"businessContext":{"privateIPAddresses":["some_private_ip_address"],"publicIPAddresses":["some_public_ip_address"],"hostnames":["some_hostname"],"resourceTypes":"rtype","accountID":"accountId","region":"north","resourceID":"an_arn","tags":{"tag1":"value1"}}}`, expectedLastScannedString))
	partial := NexposeAttributedAssetVulnerabilities{}
	err := json.Unmarshal(b, &partial)
	require.Nil(t, err)

	expectedNestedAssessmentResults := make([]AssessmentResult, 1)
	expectedNestedAssessmentResults[0] = AssessmentResult{
		Port:     3,
		Protocol: "udp",
		Proof:    "I said it",
	}

	expectedNestedAssetVulnerabilityDetailsSolutions := make([]string, 1)
	expectedNestedAssetVulnerabilityDetailsSolutions[0] = "solution"

	expectedNestedAssetVulnerabilityDetails := make([]AssetVulnerabilityDetails, 1)
	expectedNestedAssetVulnerabilityDetails[0] = AssetVulnerabilityDetails{
		ID:             "a",
		Results:        expectedNestedAssessmentResults,
		Status:         "done",
		CvssV2Score:    42,
		CvssV2Severity: "uhh, low",
		Description:    "it's bad, you know",
		Title:          "title here",
		Solutions:      expectedNestedAssetVulnerabilityDetailsSolutions,
	}

	expectedNested := NexposeAssetVulnerabilities{
		ID:              1,
		Hostname:        "bowser",
		ScanTime:        expectedLastScanned,
		IP:              "9.8.7.6",
		Vulnerabilities: expectedNestedAssetVulnerabilityDetails,
	}

	expectedPrivateIPAddresses := make([]string, 1)
	expectedPrivateIPAddresses[0] = "some_private_ip_address"

	expectedPublicIPAddresses := make([]string, 1)
	expectedPublicIPAddresses[0] = "some_public_ip_address"

	expectedHostnames := make([]string, 1)
	expectedHostnames[0] = "some_hostname"

	expectedTags := make(map[string]string, 1)
	expectedTags["tag1"] = "value1"

	expected := NexposeAttributedAssetVulnerabilities{
		NexposeAssetVulnerabilities: expectedNested,
		BusinessContext: CloudAssetDetails{
			PrivateIPAddresses: expectedPrivateIPAddresses,
			PublicIPAddresses:  expectedPublicIPAddresses,
			Hostnames:          expectedHostnames,
			Tags:               expectedTags,
			ResourceType:       "rtype",
			AccountID:          "accountId",
			Region:             "north",
			ResourceID:         "an_arn",
		},
	}

	require.True(t, reflect.DeepEqual(expected, partial), "marshaled object does not equal expected object")
}

func TestCustomUnmarshallingEmpty(t *testing.T) {
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
	marshaled, _ := json.Marshal(partial)
	badMarshalMsg := "You've added a new field in the struct hierarchy that is type array, slice, or map, but forgot to add custom unmarshalling logic for it"
	require.False(t, strings.Contains(string(marshaled), "null"), badMarshalMsg)

	require.True(t, reflect.DeepEqual(expected, partial), "marshaled object does not equal expected object")
}

func TestErrors(t *testing.T) {

	tc := []struct {
		name           string
		err            error
		expectedString string
	}{
		{
			name:           "AssetNotFoundError",
			err:            &AssetNotFoundError{},
			expectedString: "result not found in asset inventory",
		},
		{
			name:           "AssetInventoryRequestError",
			err:            &AssetInventoryRequestError{},
			expectedString: "request to asset inventory failed",
		},
		{
			name:           "AssetInventoryMultipleAssetsFoundError",
			err:            &AssetInventoryMultipleAssetsFoundError{},
			expectedString: "request to asset inventory returned multiple values for asset",
		},
		{
			name:           "AssetInventoryMultipleAttributionErrors",
			err:            &AssetInventoryMultipleAttributionErrors{},
			expectedString: "multiple asset attribution sources returned errors on asset",
		},
	}

	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.err.Error(), tt.expectedString)
		})
	}
}
