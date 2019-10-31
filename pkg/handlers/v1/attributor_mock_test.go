// Code generated by MockGen. DO NOT EDIT.
// Source: pkg/domain/attributor.go

// Package pkg/handlers/v1/ is a generated GoMock package.
package v1

import (
	context "context"
	reflect "reflect"

	domain "github.com/asecurityteam/nexpose-asset-attributor/pkg/domain"
	gomock "github.com/golang/mock/gomock"
)

// MockAssetAttributor is a mock of AssetAttributor interface
type MockAssetAttributor struct {
	ctrl     *gomock.Controller
	recorder *MockAssetAttributorMockRecorder
}

// MockAssetAttributorMockRecorder is the mock recorder for MockAssetAttributor
type MockAssetAttributorMockRecorder struct {
	mock *MockAssetAttributor
}

// NewMockAssetAttributor creates a new mock instance
func NewMockAssetAttributor(ctrl *gomock.Controller) *MockAssetAttributor {
	mock := &MockAssetAttributor{ctrl: ctrl}
	mock.recorder = &MockAssetAttributorMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockAssetAttributor) EXPECT() *MockAssetAttributorMockRecorder {
	return m.recorder
}

// Attribute mocks base method
func (m *MockAssetAttributor) Attribute(ctx context.Context, asset domain.NexposeAssetVulnerabilities) (domain.NexposeAttributedAssetVulnerabilities, error) {
	ret := m.ctrl.Call(m, "Attribute", ctx, asset)
	ret0, _ := ret[0].(domain.NexposeAttributedAssetVulnerabilities)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Attribute indicates an expected call of Attribute
func (mr *MockAssetAttributorMockRecorder) Attribute(ctx, asset interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Attribute", reflect.TypeOf((*MockAssetAttributor)(nil).Attribute), ctx, asset)
}

// MockAttributionFailureHandler is a mock of AttributionFailureHandler interface
type MockAttributionFailureHandler struct {
	ctrl     *gomock.Controller
	recorder *MockAttributionFailureHandlerMockRecorder
}

// MockAttributionFailureHandlerMockRecorder is the mock recorder for MockAttributionFailureHandler
type MockAttributionFailureHandlerMockRecorder struct {
	mock *MockAttributionFailureHandler
}

// NewMockAttributionFailureHandler creates a new mock instance
func NewMockAttributionFailureHandler(ctrl *gomock.Controller) *MockAttributionFailureHandler {
	mock := &MockAttributionFailureHandler{ctrl: ctrl}
	mock.recorder = &MockAttributionFailureHandlerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockAttributionFailureHandler) EXPECT() *MockAttributionFailureHandlerMockRecorder {
	return m.recorder
}

// HandleAttributionFailure mocks base method
func (m *MockAttributionFailureHandler) HandleAttributionFailure(ctx context.Context, failedAttributedAsset domain.NexposeAttributedAssetVulnerabilities, failure error) error {
	ret := m.ctrl.Call(m, "HandleAttributionFailure", ctx, failedAttributedAsset, failure)
	ret0, _ := ret[0].(error)
	return ret0
}

// HandleAttributionFailure indicates an expected call of HandleAttributionFailure
func (mr *MockAttributionFailureHandlerMockRecorder) HandleAttributionFailure(ctx, failedAttributedAsset, failure interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "HandleAttributionFailure", reflect.TypeOf((*MockAttributionFailureHandler)(nil).HandleAttributionFailure), ctx, failedAttributedAsset, failure)
}
