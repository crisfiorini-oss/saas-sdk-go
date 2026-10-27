package moduleauthority

import (
	"context"
	"fmt"

	"connectrpc.com/connect"
	"github.com/codefly-dev/core/wool"
	v1 "github.com/codefly-dev/saas-sdk-go/gen/saas/accounts/v1"
)

// JournalReaderConfig supplies Accounts' transport and a source of module Work
// Contexts valid for the host module-capabilities audience. The caller must
// compose a compatible issuer; generic Authority Issue does not mint this
// unbound identity. The reader receives no workload credential.
type JournalReaderConfig struct {
	Authority         Authority
	AllowInsecureHTTP bool
	WorkContext       func(context.Context) (string, error)
}

// JournalReader uses the existing Accounts transport and journal decoder with
// caller-supplied authority. It never contacts the legacy gateway broker or
// caches a capability. The caller bounds the context of issuance and the read.
type JournalReader struct {
	authority authorityEndpoint
	context   func(context.Context) (string, error)
}

func NewJournalReader(config JournalReaderConfig) (*JournalReader, error) {
	if config.WorkContext == nil {
		return nil, fmt.Errorf("%w: a journal module Work Context source is required", ErrInvalidSeams)
	}
	endpoint, err := newAuthorityEndpoint(Seams{Authority: config.Authority, AllowInsecureHTTP: config.AllowInsecureHTTP})
	if err != nil {
		return nil, err
	}
	return &JournalReader{authority: endpoint, context: config.WorkContext}, nil
}

// Close releases the existing transport's idle connections.
func (r *JournalReader) Close() error { r.authority.close(); return nil }

// ReadJournal validates through the same facade as Client.ReadJournal, then
// obtains one fresh module capability and makes one bounded Accounts read.
func (r *JournalReader) ReadJournal(ctx context.Context, after string, limit int32, types, bindings []string) (JournalPage, error) {
	return readJournal(ctx, after, limit, types, bindings, func(ctx context.Context, request *v1.ModuleReadJournalRequest) (*v1.ModuleReadJournalResponse, error) {
		token, err := r.context(ctx)
		if err != nil {
			return nil, err
		}
		if !sealed(token) {
			return nil, ErrInvalidCapability
		}
		req := connect.NewRequest(request)
		req.Header().Set(wool.WorkContextHeader, token)
		response, err := r.authority.capabilities.ReadJournal(ctx, req)
		if err != nil {
			return nil, err
		}
		if response == nil || response.Msg == nil {
			return nil, ErrInvalidJournalPage
		}
		for _, entry := range response.Msg.GetEntries() {
			if entry == nil || entry.GetOccurredAt().CheckValid() != nil {
				return nil, ErrInvalidJournalPage
			}
		}
		return response.Msg, nil
	})
}
