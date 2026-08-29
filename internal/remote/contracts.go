// Package remote reserves the typed boundary for future monitoring/website
// asset queries and mutations. v0.1 intentionally ships no implementation:
// connection configuration is local, while remote business operations require
// a separately frozen server API, authorization and audit model.
package remote

import (
	"context"
	"encoding/json"
	"errors"
)

var ErrNotImplemented = errors.New("remote asset API is reserved but not implemented in v0.1")

type Target string

const (
	Monitoring Target = "monitoring"
	Website    Target = "website"
)

type QueryRequest struct {
	SchemaVersion int               `json:"schemaVersion"`
	Resource      string            `json:"resource"`
	Reference     string            `json:"reference,omitempty"`
	Filters       map[string]string `json:"filters,omitempty"`
}
type QueryResponse struct {
	SchemaVersion int               `json:"schemaVersion"`
	Revision      string            `json:"revision"`
	Items         []json.RawMessage `json:"items"`
}
type ModifyRequest struct {
	SchemaVersion    int             `json:"schemaVersion"`
	OperationID      string          `json:"operationId"`
	Resource         string          `json:"resource"`
	Reference        string          `json:"reference"`
	ExpectedRevision string          `json:"expectedRevision"`
	Patch            json.RawMessage `json:"patch"`
	OperatorRef      string          `json:"operatorRef"`
	ApprovalRef      string          `json:"approvalRef,omitempty"`
}
type ModifyReceipt struct {
	SchemaVersion int    `json:"schemaVersion"`
	OperationID   string `json:"operationId"`
	State         string `json:"state"`
	Revision      string `json:"revision,omitempty"`
	Code          string `json:"code"`
}

type AssetClient interface {
	Query(context.Context, Target, QueryRequest) (QueryResponse, error)
	Modify(context.Context, Target, ModifyRequest) (ModifyReceipt, error)
}
