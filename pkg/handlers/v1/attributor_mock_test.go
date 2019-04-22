// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/asecurityteam/nexpose-asset-attributor/pkg/domain (interfaces: AssetAttributor)

// Package v1 is a generated GoMock package.
package v1

import (
	context "context"
	domain "github.com/asecurityteam/nexpose-asset-attributor/pkg/domain"
	gomock "github.com/golang/mock/gomock"
	reflect "reflect"
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
func (m *MockAssetAttributor) Attribute(arg0 context.Context, arg1 domain.NexposeAssetVulnerabilities) (domain.NexposeAttributedAssetVulnerabilities, error) {
	ret := m.ctrl.Call(m, "Attribute", arg0, arg1)
	ret0, _ := ret[0].(domain.NexposeAttributedAssetVulnerabilities)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Attribute indicates an expected call of Attribute
func (mr *MockAssetAttributorMockRecorder) Attribute(arg0, arg1 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Attribute", reflect.TypeOf((*MockAssetAttributor)(nil).Attribute), arg0, arg1)
}