package assetattributor

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"sync"
	"time"

	httpclient "github.com/asecurityteam/component-httpclient"
	"github.com/asecurityteam/nexpose-asset-attributor/pkg/domain"
)

const (
	cloudAssetInventoryIdentifier = "asset-inventory-api"
	timeQueryParam                = "time"
	resourcePathTypeIP            = "ip"
	resourcePathTypeHostname      = "hostname"
)

// CloudAssetInventoryConfig contains settings for the CloudAssetInventoryComponent.
type CloudAssetInventoryConfig struct {
	HTTP     *httpclient.Config
	Endpoint string `description:"The URL of asset-inventory-api's cloud endpoint."`
}

// Name of the configuration root.
func (*CloudAssetInventoryConfig) Name() string {
	return "CloudAssetInventory"
}

// CloudAssetInventoryComponent is the component for the cloud asset inventory client.
type CloudAssetInventoryComponent struct {
	HTTP     *httpclient.Component
	Endpoint *url.URL
}

// NewCloudAssetInventoryComponent generates a CloudAssetInventoryComponent.
func NewCloudAssetInventoryComponent() *CloudAssetInventoryComponent {
	return &CloudAssetInventoryComponent{
		HTTP: httpclient.NewComponent(),
	}
}

// Settings generates the default configuration.
func (c *CloudAssetInventoryComponent) Settings() *CloudAssetInventoryConfig {
	return &CloudAssetInventoryConfig{
		HTTP: c.HTTP.Settings(),
	}
}

// New generates a Subcription decorator.
func (c *CloudAssetInventoryComponent) New(ctx context.Context, conf *CloudAssetInventoryConfig) (*CloudAssetInventory, error) {
	rt, e := c.HTTP.New(ctx, conf.HTTP)
	if e != nil {
		return nil, e
	}
	u, e := url.Parse(conf.Endpoint)
	if e != nil {
		return nil, e
	}
	return &CloudAssetInventory{
		Client: &http.Client{
			Transport: rt,
		},
		Endpoint: u,
	}, nil
}

type cloudAssetInventoryResponse struct {
	Response []domain.CloudAssetDetails `json:"response"`
}

// CloudAssetInventory is an implementation of AssetAttributor that queries the
// asecurityteam/asset-inventory-api service's cloud asset API.
type CloudAssetInventory struct {
	Client   *http.Client
	Endpoint *url.URL
}

// Attribute queries the asecurityteam/asset-inventory-api service first by IP, then by hostname
// if the first query returns no results
func (n *CloudAssetInventory) Attribute(ctx context.Context, asset domain.NexposeAssetVulnerabilities) (domain.NexposeAttributedAssetVulnerabilities, error) {
	if asset.LastScanned.IsZero() {
		return domain.NexposeAttributedAssetVulnerabilities{}, fmt.Errorf("no valid timestamp in scan history")
	}

	if asset.IP == "" && asset.Hostname == "" {
		return domain.NexposeAttributedAssetVulnerabilities{}, domain.AssetNotFoundError{
			Inner:          fmt.Errorf("asset has no IP or hostname"),
			AssetID:        fmt.Sprintf("%d", asset.ID),
			ScanTimestamp:  asset.LastScanned.Format(time.RFC3339Nano),
			AssetInventory: cloudAssetInventoryIdentifier,
		}
	}

	// Since asset-inventory-api has APIs for asset lookup by both IP and hostname, make concurrent
	// calls to asset-inventory-api's APIs for asset lookup by IP and hostname, wait for the calls
	// to complete, and aggregrate the responses and errors onto buffered channels.
	assetDetailsChan := make(chan domain.CloudAssetDetails, 2)
	errChan := make(chan error, 2)
	wg := &sync.WaitGroup{}

	if asset.IP != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			assetDetails, err := n.fetchAsset(ctx, resourcePathTypeIP, asset.IP, asset.LastScanned)
			if err != nil {
				errChan <- err
				return
			}
			assetDetailsChan <- assetDetails[0]
		}()
	}

	if asset.Hostname != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			assetDetails, err := n.fetchAsset(ctx, resourcePathTypeHostname, asset.Hostname, asset.LastScanned)
			if err != nil {
				errChan <- err
				return
			}
			assetDetailsChan <- assetDetails[0]
		}()
	}
	wg.Wait()

	// Once all goroutines have completed and all errors received, close the error channel and
	// range over the buffered output, exiting on any fatal errors.
	close(errChan)
	outerErrs := []error{}
	for e := range errChan {
		switch e.(type) {
		case httpMultipleAssetsFoundError:
			return domain.NexposeAttributedAssetVulnerabilities{}, domain.AssetInventoryMultipleAssetsFoundError{
				Inner:          e,
				AssetID:        fmt.Sprintf("%d", asset.ID),
				ScanTimestamp:  asset.LastScanned.Format(time.RFC3339Nano),
				AssetInventory: cloudAssetInventoryIdentifier,
			}
		case httpBadRequest:
			return domain.NexposeAttributedAssetVulnerabilities{}, domain.AssetInventoryRequestError{
				Inner:          e,
				AssetID:        fmt.Sprintf("%d", asset.ID),
				ScanTimestamp:  asset.LastScanned.Format(time.RFC3339Nano),
				AssetInventory: cloudAssetInventoryIdentifier,
				Code:           http.StatusBadRequest,
			}
		}
		outerErrs = append(outerErrs, e)
	}

	// Exit with an AssetNotFoundError error if both API calls returned non-fatal errors.
	if len(outerErrs) == 2 {
		return domain.NexposeAttributedAssetVulnerabilities{}, domain.AssetNotFoundError{
			Inner:          combinedError{Errors: outerErrs},
			AssetID:        fmt.Sprintf("%d", asset.ID),
			ScanTimestamp:  asset.LastScanned.Format(time.RFC3339Nano),
			AssetInventory: cloudAssetInventoryIdentifier,
		}
	}

	// Close the assetDetailsChan channel and append the buffered output to a slice.
	close(assetDetailsChan)
	assetDetails := []domain.CloudAssetDetails{}
	for assetDetail := range assetDetailsChan {
		assetDetails = append(assetDetails, assetDetail)
	}

	// Return the attributed asset with the first assetDetails returned by asset-inventory-api
	return domain.NexposeAttributedAssetVulnerabilities{
		NexposeAssetVulnerabilities: asset,
		BusinessContext:             assetDetails[0],
	}, nil
}

func (n *CloudAssetInventory) fetchAsset(ctx context.Context, idType string, id string, ts time.Time) ([]domain.CloudAssetDetails, error) {
	u, _ := url.Parse(n.Endpoint.String())
	u.Path = path.Join(u.Path, idType, id)
	q := u.Query()
	q.Set(timeQueryParam, ts.Format(time.RFC3339Nano))
	u.RawQuery = q.Encode()

	req, _ := http.NewRequest(http.MethodGet, u.String(), http.NoBody)
	resp, e := n.Client.Do(req.WithContext(ctx))
	if e != nil {
		return []domain.CloudAssetDetails{}, e
	}
	defer resp.Body.Close()
	respBody, e := ioutil.ReadAll(resp.Body)
	if e != nil {
		return []domain.CloudAssetDetails{}, e
	}

	switch {
	case resp.StatusCode == http.StatusNotFound:
		return []domain.CloudAssetDetails{}, httpNotFound{ID: id, Type: idType}
	case resp.StatusCode == http.StatusBadRequest:
		return []domain.CloudAssetDetails{}, httpBadRequest{ID: id, Type: idType, Reason: string(respBody)}
	case resp.StatusCode != http.StatusOK:
		return []domain.CloudAssetDetails{}, httpRequestError{ID: id, Type: idType, Reason: string(respBody)}
	}

	var assetDetails cloudAssetInventoryResponse
	if e := json.Unmarshal(respBody, &assetDetails); e != nil {
		return []domain.CloudAssetDetails{}, e
	}

	// a successful call with no results is treated as a not found error
	if len(assetDetails.Response) == 0 {
		return []domain.CloudAssetDetails{}, httpNotFound{ID: id, Type: idType}
	}
	// if the asset-inventory-api returns multiple assets, there's no way to determine which
	// is the "correct" one, so it is treated as an error
	if len(assetDetails.Response) > 1 {
		foundAssets := []string{}
		for _, assetDetail := range assetDetails.Response {
			foundAssets = append(foundAssets, assetDetail.ARN)
		}
		return []domain.CloudAssetDetails{}, httpMultipleAssetsFoundError{ID: id, Type: idType, FoundAssets: foundAssets}
	}

	return assetDetails.Response, nil
}
