package domain

import (
	"context"
	"encoding/json"
	"reflect"
	"time"
)

// AssetAttributor receives a NexposeAssetVulnerabilities instance, queries one
// or more asset inventory systems, and returns a NexposeAttributedAssetVulnerabilities
// instance annotated with the business context for the asset at scan time.
type AssetAttributor interface {
	Attribute(ctx context.Context, asset NexposeAssetVulnerabilities) (NexposeAttributedAssetVulnerabilities, error)
}

// NexposeAssetVulnerabilities is a Nexpose asset response payload appended
// with assetVulnerabilityDetails
type NexposeAssetVulnerabilities struct {
	ScanTime        time.Time                   `json:"scanTime"`
	Hostname        string                      `json:"hostname"`
	ID              int64                       `json:"id"`
	IP              string                      `json:"ip"`
	Vulnerabilities []AssetVulnerabilityDetails `json:"assetVulnerabilityDetails"`
}

// CloudAssetDetails represent a cloud asset and associated metadata
type CloudAssetDetails struct {
	PrivateIPAddresses []string          `json:"privateIPAddresses"`
	PublicIPAddresses  []string          `json:"publicIPAddresses"`
	Hostnames          []string          `json:"hostnames"`
	ResourceType       string            `json:"resourceTypes"`
	AccountID          string            `json:"accountID"`
	Region             string            `json:"region"`
	ResourceID         string            `json:"resourceID"`
	Tags               map[string]string `json:"tags"`
}

// NexposeAttributedAssetVulnerabilities is a NexposeAssetVulnerabilities instance combined
// with the business context pertaining to the asset at scan time.
type NexposeAttributedAssetVulnerabilities struct {
	NexposeAssetVulnerabilities
	BusinessContext CloudAssetDetails `json:"businessContext"`
}

// UnmarshalJSON is a custom unmarshaller to ensure no `nil` or `null` fields in the resulting struct
func (n *NexposeAttributedAssetVulnerabilities) UnmarshalJSON(data []byte) error {
	type Alias NexposeAttributedAssetVulnerabilities
	aux := &struct {
		*Alias
	}{
		Alias: (*Alias)(n),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if n.NexposeAssetVulnerabilities.Vulnerabilities == nil {
		n.NexposeAssetVulnerabilities.Vulnerabilities = make([]AssetVulnerabilityDetails, 0)
	}

	if reflect.DeepEqual((CloudAssetDetails{}), n.BusinessContext) {
		if err := json.Unmarshal(data, &n.BusinessContext); err != nil {
			return err
		}
	}

	return nil
}

// UnmarshalJSON is a custom unmarshaller to ensure no `nil` or `null` fields in the resulting struct
func (n *CloudAssetDetails) UnmarshalJSON(data []byte) error {
	type Alias CloudAssetDetails
	aux := &struct {
		*Alias
	}{
		Alias: (*Alias)(n),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if n.Hostnames == nil {
		n.Hostnames = make([]string, 0)
	}
	if n.PrivateIPAddresses == nil {
		n.PrivateIPAddresses = make([]string, 0)
	}
	if n.PublicIPAddresses == nil {
		n.PublicIPAddresses = make([]string, 0)
	}
	if n.Tags == nil {
		n.Tags = make(map[string]string)
	}

	return nil
}

// AssetNotFoundError occurs when a request to an asset inventory system
// returns either a 404 Not Found response, or a 200 OK response with no results
type AssetNotFoundError struct {
	Inner          error
	AssetInventory string
	Code           int
	ScanTimestamp  string
}

func (err AssetNotFoundError) Error() string {
	return "result not found in asset inventory"
}

// AssetInventoryRequestError occurs when a request to an asset inventory system
// returns a failure response
type AssetInventoryRequestError struct {
	Inner          error
	AssetInventory string
	Code           int
	ScanTimestamp  string
}

func (err AssetInventoryRequestError) Error() string {
	return "request to asset inventory failed"
}

// AssetInventoryMultipleAssetsFoundError occurs when a request to an asset inventory system
// returns a successful response with multiple assets
type AssetInventoryMultipleAssetsFoundError struct {
	Inner          error
	AssetInventory string
	ScanTimestamp  string
}

func (err AssetInventoryMultipleAssetsFoundError) Error() string {
	return "request to asset inventory returned multiple values for asset"
}

// AssetInventoryMultipleAttributionErrors occurs when multiple attribution errors
// occur on multiple attribution sources
type AssetInventoryMultipleAttributionErrors struct {
	Inner          error
	ScanTimestamp  string
	AssetInventory string
}

func (err AssetInventoryMultipleAttributionErrors) Error() string {
	return "multiple asset attribution sources returned errors on asset"
}

// AttributionFailureHandler is an interface that handles assets that could not be completely
// attributed. The methods to implement might vary organization to organization
type AttributionFailureHandler interface {
	// This method is left to the discretion of the organization. For example, we may want to store their attribution failures encrypted
	// in a persistent store, while others may want to persist theirs in a long-lived encrypted queue, or rely on a streaming platform
	// like Kafka to keep the data until it can be investigated.
	HandleAttributionFailure(ctx context.Context, failedAttributedAsset NexposeAttributedAssetVulnerabilities, failure error) error
}
