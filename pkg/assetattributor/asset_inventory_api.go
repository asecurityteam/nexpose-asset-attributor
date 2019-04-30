package assetattributor

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"time"

	"github.com/asecurityteam/nexpose-asset-attributor/pkg/domain"
)

const (
	assetHistoryTypeScan        = "SCAN"
	assetInventoryAPIIdentifier = "asset-inventory-api"
	timeQueryParam              = "time"
	resourcePathTypeIP          = "ip"
	resourcePathTypeHostname    = "hostname"
)

type assetInventoryResponse struct {
	Response []domain.CloudAssetDetails `json:"response"`
}

// AssetInventoryAPIAttributor is an implementation of AssetAttributor that queries the
// asecurityteam/asset-inventory-api service
type AssetInventoryAPIAttributor struct {
	Client         *http.Client
	Host           string
	CloudAssetPath string
}

// Attribute queries the asecurityteam/asset-inventory-api service first by IP, then by hostname
// if the first query returns no results
func (n *AssetInventoryAPIAttributor) Attribute(ctx context.Context, asset domain.NexposeAssetVulnerabilities) (domain.NexposeAttributedAssetVulnerabilities, error) {
	ts, err := extractTimestamp(asset.History)
	if err != nil {
		return domain.NexposeAttributedAssetVulnerabilities{}, err
	}

	if asset.IP == "" && asset.HostName == "" {
		return domain.NexposeAttributedAssetVulnerabilities{}, domain.AssetNotFoundError{
			Inner:          fmt.Errorf("asset has no IP or hostname"),
			AssetID:        fmt.Sprintf("%d", asset.ID),
			ScanTimestamp:  ts.Format(time.RFC3339Nano),
			AssetInventory: assetInventoryAPIIdentifier,
		}
	}

	outerErrs := []error{}

	// first query asset-inventory-api by IP if possible
	if asset.IP != "" {
		assetDetails, e := n.fetchAsset(ctx, resourcePathTypeIP, asset.IP, ts)
		switch e.(type) {
		case nil:
			return domain.NexposeAttributedAssetVulnerabilities{
				Asset:           asset.Asset,
				Vulnerabilities: asset.Vulnerabilities,
				BusinessContext: assetDetails[0],
			}, nil
		case httpMultipleAssetsFoundError:
			return domain.NexposeAttributedAssetVulnerabilities{}, domain.AssetInventoryMultipleAssetsFoundError{
				Inner:          e,
				AssetID:        fmt.Sprintf("%d", asset.ID),
				ScanTimestamp:  ts.Format(time.RFC3339Nano),
				AssetInventory: assetInventoryAPIIdentifier,
			}
		case httpBadRequest:
			return domain.NexposeAttributedAssetVulnerabilities{}, domain.AssetInventoryRequestError{
				Inner:          e,
				AssetID:        fmt.Sprintf("%d", asset.ID),
				ScanTimestamp:  ts.Format(time.RFC3339Nano),
				AssetInventory: assetInventoryAPIIdentifier,
				Code:           http.StatusBadRequest,
			}
		default:
			outerErrs = append(outerErrs, e)
		}
	}

	// query asset-inventory-api by hostname if IP is not available or returns no results
	if asset.HostName != "" {
		assetDetails, e := n.fetchAsset(ctx, resourcePathTypeHostname, asset.HostName, ts)
		switch e.(type) {
		case nil:
			return domain.NexposeAttributedAssetVulnerabilities{
				Asset:           asset.Asset,
				Vulnerabilities: asset.Vulnerabilities,
				BusinessContext: assetDetails[0],
			}, nil
		case httpMultipleAssetsFoundError:
			return domain.NexposeAttributedAssetVulnerabilities{}, domain.AssetInventoryMultipleAssetsFoundError{
				Inner:          e,
				AssetID:        fmt.Sprintf("%d", asset.ID),
				ScanTimestamp:  ts.Format(time.RFC3339Nano),
				AssetInventory: assetInventoryAPIIdentifier,
			}
		case httpBadRequest:
			return domain.NexposeAttributedAssetVulnerabilities{}, domain.AssetInventoryRequestError{
				Inner:          e,
				AssetID:        fmt.Sprintf("%d", asset.ID),
				ScanTimestamp:  ts.Format(time.RFC3339Nano),
				AssetInventory: assetInventoryAPIIdentifier,
				Code:           http.StatusBadRequest,
			}
		default:
			outerErrs = append(outerErrs, e)
		}
	}

	// combine any errors from the individual calls to asset-inventory-api and
	// return an AssetNotFoundError
	return domain.NexposeAttributedAssetVulnerabilities{}, domain.AssetNotFoundError{
		Inner:          combinedError{Errors: outerErrs},
		AssetID:        fmt.Sprintf("%d", asset.ID),
		ScanTimestamp:  ts.Format(time.RFC3339Nano),
		AssetInventory: assetInventoryAPIIdentifier,
	}
}

func (n *AssetInventoryAPIAttributor) fetchAsset(ctx context.Context, idType string, id string, ts time.Time) ([]domain.CloudAssetDetails, error) {
	u, e := url.Parse(n.Host)
	if e != nil {
		return []domain.CloudAssetDetails{}, e
	}
	u.Path = path.Join(u.Path, n.CloudAssetPath, idType, id)
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

	var assetDetails assetInventoryResponse
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

func extractTimestamp(history []domain.AssetHistory) (time.Time, error) {
	latestTime := time.Time{}
	for _, evt := range history {
		if evt.Type == assetHistoryTypeScan {
			t, err := time.Parse(time.RFC3339, evt.Date)
			if err != nil {
				return latestTime, err
			}
			if t.After(latestTime) {
				latestTime = t
			}
		}
	}
	if latestTime.IsZero() {
		return time.Time{}, fmt.Errorf("no valid timestamp in scan history")
	}
	return latestTime, nil
}
