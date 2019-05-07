package assetattributor

import (
	"fmt"
	"strings"
)

// httpNotFound occurs when when a request to an asset inventory system returns a 404
type httpNotFound struct {
	ID   string
	Type string
}

func (err httpNotFound) Error() string {
	return fmt.Sprintf("%s %s not found", err.Type, err.ID)
}

// httpBadRequest occurs when when a request to an asset inventory system returns a 400
type httpBadRequest struct {
	ID     string
	Type   string
	Reason string
}

func (err httpBadRequest) Error() string {
	return fmt.Sprintf("bad request for %s %s: %s", err.Type, err.ID, err.Reason)
}

// httpRequestError occurs when when a request to an asset inventory system returns a 5XX error
type httpRequestError struct {
	ID     string
	Type   string
	Reason string
}

func (err httpRequestError) Error() string {
	return fmt.Sprintf("request error for %s %s: %s", err.Type, err.ID, err.Reason)
}

// httpMultipleAssetsFoundError occurs when when a request to an asset inventory system successfully returns
// multiple assets
type httpMultipleAssetsFoundError struct {
	ID          string
	Type        string
	FoundAssets []string
}

func (err httpMultipleAssetsFoundError) Error() string {
	return fmt.Sprintf("request for %s %s returned multiple results: %s", err.Type, err.ID, strings.Join(err.FoundAssets, ", "))
}

// combinedError combines multiple error strings in a single message
type combinedError struct {
	Errors []error
}

func (err combinedError) Error() string {
	return fmt.Sprintf("errors: %v", err.Errors)
}
