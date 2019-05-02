package assetattributor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"testing"
	"time"

	"github.com/golang/mock/gomock"

	"github.com/asecurityteam/nexpose-asset-attributor/pkg/domain"
	"github.com/stretchr/testify/require"
)

var testIP = "1.2.3.4"
var testHostname = "hostname"
var testTimestamp = time.Date(2019, time.April, 22, 15, 2, 44, 0, time.UTC)
var errReason = ""

func TestAssetInventoryAPIAttributorAttribute(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockRT := NewMockRoundTripper(ctrl)

	attributor := AssetInventoryAPIAttributor{
		Client:         &http.Client{Transport: mockRT},
		Host:           "http://localhost",
		CloudAssetPath: "/v1/cloud",
	}

	testAssetDetails := domain.CloudAssetDetails{
		PrivateIPAddresses: []string{testIP},
		PublicIPAddresses:  []string{testIP},
		Hostnames:          []string{testHostname},
		ResourceType:       "ec2",
		AccountID:          "1234567890",
		ARN:                "123",
		Region:             "us-west-2",
		Tags:               map[string]string{"key": "value"},
	}

	tc := []struct {
		name        string
		asset       domain.NexposeAssetVulnerabilities
		resps       []assetInventoryResponse
		respCodes   []int
		errExpected bool
		err         error
	}{
		{
			name: "success",
			asset: domain.NexposeAssetVulnerabilities{
				ID:          1,
				LastScanned: testTimestamp,
				IP:          testIP,
				Hostname:    testHostname,
			},
			resps: []assetInventoryResponse{
				{
					Response: []domain.CloudAssetDetails{
						testAssetDetails,
					},
				},
				{
					Response: []domain.CloudAssetDetails{
						testAssetDetails,
					},
				},
			},
			respCodes:   []int{http.StatusOK, http.StatusOK},
			errExpected: false,
			err:         nil,
		},
		{
			name: "bad request error",
			asset: domain.NexposeAssetVulnerabilities{
				ID:          1,
				LastScanned: testTimestamp,
				IP:          testIP,
				Hostname:    testHostname,
			},
			resps: []assetInventoryResponse{
				{},
				{
					Response: []domain.CloudAssetDetails{
						testAssetDetails,
					},
				},
			},
			respCodes:   []int{http.StatusBadRequest, http.StatusOK},
			errExpected: true,
			err:         domain.AssetInventoryRequestError{},
		},
		{
			name: "multiple assets error",
			asset: domain.NexposeAssetVulnerabilities{
				ID:          1,
				LastScanned: testTimestamp,
				IP:          testIP,
				Hostname:    testHostname,
			},
			resps: []assetInventoryResponse{
				{
					Response: []domain.CloudAssetDetails{
						testAssetDetails,
						testAssetDetails,
					},
				},
				{
					Response: []domain.CloudAssetDetails{
						testAssetDetails,
					},
				},
			},
			respCodes:   []int{http.StatusOK, http.StatusOK},
			errExpected: true,
			err:         domain.AssetInventoryMultipleAssetsFoundError{},
		},
		{
			name: "multiple non-fatal errors",
			asset: domain.NexposeAssetVulnerabilities{
				ID:          1,
				LastScanned: testTimestamp,
				IP:          testIP,
				Hostname:    testHostname,
			},
			resps: []assetInventoryResponse{
				{},
				{},
			},
			respCodes:   []int{http.StatusNotFound, http.StatusNotFound},
			errExpected: true,
			err:         domain.AssetNotFoundError{},
		},
	}

	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			for i := range tt.resps {
				respJSON, _ := json.Marshal(tt.resps[i])
				mockRT.EXPECT().RoundTrip(gomock.Any()).Return(&http.Response{
					Body:       ioutil.NopCloser(bytes.NewReader(respJSON)),
					StatusCode: tt.respCodes[i],
				}, nil)
			}
			_, err := attributor.Attribute(context.Background(), tt.asset)
			if tt.errExpected {
				require.IsType(t, tt.err, err)
			} else {
				require.Nil(t, err)
			}
		})
	}
}

func TestAssetInventoryAPIAttributorAttributeInvalidAssetTimestamp(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockRT := NewMockRoundTripper(ctrl)

	attributor := AssetInventoryAPIAttributor{
		Client:         &http.Client{Transport: mockRT},
		Host:           "http://localhost",
		CloudAssetPath: "/v1/cloud",
	}

	testAsset := domain.NexposeAssetVulnerabilities{
		ID:          1,
		LastScanned: time.Time{},
		IP:          testIP,
		Hostname:    testHostname,
	}
	_, err := attributor.Attribute(context.Background(), testAsset)
	require.Error(t, err)
}

func TestAssetInventoryAPIAttributorAttributeNoHostnameOrIP(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockRT := NewMockRoundTripper(ctrl)

	attributor := AssetInventoryAPIAttributor{
		Client:         &http.Client{Transport: mockRT},
		Host:           "http://localhost",
		CloudAssetPath: "/v1/cloud",
	}

	testAsset := domain.NexposeAssetVulnerabilities{
		ID:          1,
		LastScanned: time.Date(2019, time.April, 22, 15, 2, 44, 0, time.UTC),
	}

	_, err := attributor.Attribute(context.Background(), testAsset)
	require.Error(t, err)
	require.IsType(t, domain.AssetNotFoundError{}, err)
}

func TestFetchAssetValidResponses(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockRT := NewMockRoundTripper(ctrl)

	attributor := AssetInventoryAPIAttributor{
		Client:         &http.Client{Transport: mockRT},
		Host:           "http://localhost",
		CloudAssetPath: "/v1/cloud",
	}

	tc := []struct {
		name        string
		resp        []domain.CloudAssetDetails
		errExpected bool
		err         error
	}{
		{
			name: "success",
			resp: []domain.CloudAssetDetails{
				{
					PrivateIPAddresses: []string{testIP},
					PublicIPAddresses:  []string{testIP},
					Hostnames:          []string{testHostname},
					ResourceType:       "ec2",
					AccountID:          "1234567890",
					ARN:                "123",
					Region:             "us-west-2",
					Tags:               map[string]string{"key": "value"},
				},
			},
			errExpected: false,
			err:         nil,
		},
		{
			name: "multiple CloudAssetDetails in response",
			resp: []domain.CloudAssetDetails{
				{
					PrivateIPAddresses: []string{testIP},
					PublicIPAddresses:  []string{testIP},
					Hostnames:          []string{testHostname},
					ResourceType:       "ec2",
					AccountID:          "1234567890",
					ARN:                "123",
					Region:             "us-west-2",
					Tags:               map[string]string{"key": "value"},
				},
				{
					PrivateIPAddresses: []string{testIP},
					PublicIPAddresses:  []string{testIP},
					Hostnames:          []string{testHostname},
					ResourceType:       "ec2",
					AccountID:          "1234567890",
					ARN:                "321",
					Region:             "us-west-2",
					Tags:               map[string]string{"key": "value"},
				},
			},
			errExpected: true,
			err:         httpMultipleAssetsFoundError{ID: testIP, Type: resourcePathTypeIP, FoundAssets: []string{"123", "321"}},
		},
		{
			name:        "no CloudAssetDetails in response",
			resp:        []domain.CloudAssetDetails{},
			errExpected: true,
			err:         httpNotFound{ID: testIP, Type: resourcePathTypeIP},
		},
	}

	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			resp := assetInventoryResponse{Response: tt.resp}
			respJSON, _ := json.Marshal(resp)
			mockRT.EXPECT().RoundTrip(gomock.Any()).Return(&http.Response{
				Body:       ioutil.NopCloser(bytes.NewReader(respJSON)),
				StatusCode: http.StatusOK,
			}, nil)
			assetDetails, err := attributor.fetchAsset(context.Background(), resourcePathTypeIP, testIP, time.Time{})
			if tt.errExpected {
				require.EqualError(t, err, tt.err.Error())
				require.Equal(t, []domain.CloudAssetDetails{}, assetDetails)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.resp, assetDetails)
			}
		})
	}

	mockRT.EXPECT().RoundTrip(gomock.Any()).Return(&http.Response{
		Body:       ioutil.NopCloser(bytes.NewReader([]byte("foo"))),
		StatusCode: http.StatusOK,
	}, nil)
	_, err := attributor.fetchAsset(context.Background(), resourcePathTypeIP, testIP, time.Time{})
	require.Error(t, err)
}

func TestFetchAssetUnmarshallError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockRT := NewMockRoundTripper(ctrl)

	attributor := AssetInventoryAPIAttributor{
		Client: &http.Client{Transport: mockRT},
		Host:   "http://localhost",
	}
	mockRT.EXPECT().RoundTrip(gomock.Any()).Return(&http.Response{
		Body:       ioutil.NopCloser(bytes.NewReader([]byte("foo"))),
		StatusCode: http.StatusOK,
	}, nil)
	_, err := attributor.fetchAsset(context.Background(), resourcePathTypeIP, testIP, time.Time{})
	require.Error(t, err)
}

func TestFetchAssetWithInvalidHost(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockRT := NewMockRoundTripper(ctrl)

	attributor := AssetInventoryAPIAttributor{
		Client:         &http.Client{Transport: mockRT},
		Host:           "~!@#$%^&*()_+:?><!@#$%^&*())_:",
		CloudAssetPath: "/v1/cloud",
	}
	_, err := attributor.fetchAsset(context.Background(), resourcePathTypeIP, testIP, time.Time{})
	require.Error(t, err)
}

func TestFetchAssetResponseError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockRT := NewMockRoundTripper(ctrl)

	attributor := AssetInventoryAPIAttributor{
		Client: &http.Client{Transport: mockRT},
		Host:   "http://localhost",
	}
	mockRT.EXPECT().RoundTrip(gomock.Any()).Return(&http.Response{
		Body: nil,
	}, fmt.Errorf("response error"))
	_, err := attributor.fetchAsset(context.Background(), resourcePathTypeIP, testIP, time.Time{})
	require.Error(t, err)
}

type errReader struct {
	Error error
}

func (r errReader) Read(_ []byte) (int, error) {
	return 0, r.Error
}

func TestFetchAssetErrorReadingResponse(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockRT := NewMockRoundTripper(ctrl)

	attributor := AssetInventoryAPIAttributor{
		Client:         &http.Client{Transport: mockRT},
		Host:           "http://localhost",
		CloudAssetPath: "/v1/cloud",
	}
	mockRT.EXPECT().RoundTrip(gomock.Any()).Return(&http.Response{
		Body:       ioutil.NopCloser(errReader{Error: fmt.Errorf("reader error")}),
		StatusCode: http.StatusOK,
	}, nil)
	_, err := attributor.fetchAsset(context.Background(), resourcePathTypeIP, testIP, time.Time{})
	require.Error(t, err)
}

func TestFetchAssetNotOKStatusCodes(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockRT := NewMockRoundTripper(ctrl)

	attributor := AssetInventoryAPIAttributor{
		Client:         &http.Client{Transport: mockRT},
		Host:           "http://localhost",
		CloudAssetPath: "/v1/cloud",
	}

	tc := []struct {
		name string
		code int
		err  error
	}{
		{
			name: "400",
			code: http.StatusBadRequest,
			err:  httpBadRequest{ID: testIP, Type: resourcePathTypeIP, Reason: errReason},
		},
		{
			name: "404",
			code: http.StatusNotFound,
			err:  httpNotFound{ID: testIP, Type: resourcePathTypeIP},
		},
		{
			name: "500",
			code: http.StatusInternalServerError,
			err:  httpRequestError{ID: testIP, Type: resourcePathTypeIP, Reason: errReason},
		},
		{
			name: "502",
			code: http.StatusBadGateway,
			err:  httpRequestError{ID: testIP, Type: resourcePathTypeIP, Reason: errReason},
		},
	}

	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			mockRT.EXPECT().RoundTrip(gomock.Any()).Return(&http.Response{
				Body:       ioutil.NopCloser(bytes.NewReader([]byte{})),
				StatusCode: tt.code,
			}, nil)
			_, err := attributor.fetchAsset(context.Background(), resourcePathTypeIP, testIP, time.Time{})
			require.EqualError(t, err, tt.err.Error())
		})
	}
}
