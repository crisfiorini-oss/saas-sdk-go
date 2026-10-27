package moduleauthority

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/codefly-dev/saas-sdk-go/gen/saas/accounts/v1"
	rpc "github.com/codefly-dev/saas-sdk-go/gen/saas/accounts/v1/accountsv1connect"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type sourceJournal struct {
	rpc.UnimplementedModuleCapabilitiesServiceHandler
	read func(context.Context, *connect.Request[v1.ModuleReadJournalRequest]) (*connect.Response[v1.ModuleReadJournalResponse], error)
}

func (s sourceJournal) ReadJournal(ctx context.Context, r *connect.Request[v1.ModuleReadJournalRequest]) (*connect.Response[v1.ModuleReadJournalResponse], error) {
	return s.read(ctx, r)
}

func journalFromSource(t *testing.T, source func(context.Context) (string, error), read func(context.Context, *connect.Request[v1.ModuleReadJournalRequest]) (*connect.Response[v1.ModuleReadJournalResponse], error)) *JournalReader {
	t.Helper()
	_, handler := rpc.NewModuleCapabilitiesServiceHandler(sourceJournal{read: read})
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc") {
			t.Error("journal did not use native HTTP/2 gRPC")
		}
		handler.ServeHTTP(w, r)
	}))
	server.Config.Protocols = new(http.Protocols)
	server.Config.Protocols.SetUnencryptedHTTP2(true)
	server.Start()
	t.Cleanup(server.Close)
	endpoint, _ := url.Parse(server.URL)
	reader, err := NewJournalReader(JournalReaderConfig{Authority: Authority{Address: endpoint.Host}, WorkContext: source})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reader.Close() })
	return reader
}

func TestJournalReaderReusesTheTransportAndObtainsFreshAuthority(t *testing.T) {
	issued := 0
	var calls atomic.Int32
	reader := journalFromSource(t, func(context.Context) (string, error) {
		issued++
		return sealedToken("source-module"), nil
	}, func(_ context.Context, request *connect.Request[v1.ModuleReadJournalRequest]) (*connect.Response[v1.ModuleReadJournalResponse], error) {
		calls.Add(1)
		if request.Header().Get("X-Codefly-Work-Context") != sealedToken("source-module") || request.Header().Get("X-Codefly-Internal-Token") != "" || request.Msg.GetAfter() != JournalStart {
			t.Error("journal used a legacy credential or changed the request")
		}
		return connect.NewResponse(&v1.ModuleReadJournalResponse{NextAfter: "p1", Entries: []*v1.ModuleJournalEntry{{Position: "p1", EventId: "event", Type: journalType, OccurredAt: timestamppb.New(journalEpoch), DeliveryMachinery: true}}}), nil
	})
	for range 2 {
		page, err := reader.ReadJournal(t.Context(), JournalStart, 100, []string{journalType}, nil)
		if err != nil || page.NextAfter != "p1" || len(page.Entries) != 1 || !page.Entries[0].DeliveryMachinery || !page.Entries[0].OccurredAt.Equal(journalEpoch) {
			t.Fatalf("journal projection: %v %v", page, err)
		}
	}
	if issued != 2 || calls.Load() != 2 {
		t.Fatal("journal reused authority or duplicated a read")
	}
	if _, err := reader.ReadJournal(t.Context(), JournalStart, 100, nil, nil); !errors.Is(err, ErrInvalidJournalRead) || issued != 2 {
		t.Fatal("invalid request obtained authority")
	}
}

func TestJournalReaderSourceFailuresAndMalformedPages(t *testing.T) {
	for _, token := range []string{"", "not-sealed"} {
		reader := journalFromSource(t, func(context.Context) (string, error) { return token, nil }, func(context.Context, *connect.Request[v1.ModuleReadJournalRequest]) (*connect.Response[v1.ModuleReadJournalResponse], error) {
			t.Fatal("invalid capability reached Accounts")
			return nil, nil
		})
		if _, err := reader.ReadJournal(t.Context(), JournalStart, 100, []string{journalType}, nil); !errors.Is(err, ErrInvalidCapability) {
			t.Fatalf("invalid source token: %v", err)
		}
	}
	refusal := errors.New("issuer refused")
	reader := journalFromSource(t, func(context.Context) (string, error) { return "", refusal }, func(context.Context, *connect.Request[v1.ModuleReadJournalRequest]) (*connect.Response[v1.ModuleReadJournalResponse], error) {
		t.Fatal("source refusal reached Accounts")
		return nil, nil
	})
	if _, err := reader.ReadJournal(t.Context(), JournalStart, 100, []string{journalType}, nil); !errors.Is(err, refusal) {
		t.Fatalf("source refusal lost: %v", err)
	}
	reader = journalFromSource(t, func(context.Context) (string, error) { return sealedToken("source-module"), nil }, func(context.Context, *connect.Request[v1.ModuleReadJournalRequest]) (*connect.Response[v1.ModuleReadJournalResponse], error) {
		return connect.NewResponse(&v1.ModuleReadJournalResponse{Entries: []*v1.ModuleJournalEntry{{Position: "p1"}}}), nil
	})
	if _, err := reader.ReadJournal(t.Context(), JournalStart, 100, []string{journalType}, nil); !errors.Is(err, ErrInvalidJournalPage) {
		t.Fatalf("malformed response accepted: %v", err)
	}
}

func TestJournalReaderSourceReceivesTheReadDeadline(t *testing.T) {
	reader := journalFromSource(t, func(ctx context.Context) (string, error) { <-ctx.Done(); return "", ctx.Err() }, func(context.Context, *connect.Request[v1.ModuleReadJournalRequest]) (*connect.Response[v1.ModuleReadJournalResponse], error) {
		t.Fatal("expired source reached Accounts")
		return nil, nil
	})
	ctx, cancel := context.WithTimeout(t.Context(), time.Millisecond)
	defer cancel()
	if _, err := reader.ReadJournal(ctx, JournalStart, 100, []string{journalType}, nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("read did not bound source issuance: %v", err)
	}
}

func TestJournalReaderRequiresAnExplicitAuthorityAndSource(t *testing.T) {
	for _, config := range []JournalReaderConfig{{}, {WorkContext: func(context.Context) (string, error) { return "", nil }}} {
		if reader, err := NewJournalReader(config); !errors.Is(err, ErrInvalidSeams) || reader != nil {
			t.Fatalf("incomplete journal configuration accepted: %v %v", reader, err)
		}
	}
}
