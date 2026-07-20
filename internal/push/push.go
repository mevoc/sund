// Package push delivers contentless wake-up pings. A ping carries nothing — no
// payload, no queue id — it only tells a device to check in; the client then
// drains its queues over the API (PRD, Push wake-up). Delivery paths differ per
// platform, so the sender is a pluggable Pinger: UnifiedPush/ntfy for Android is
// the one implemented here; an APNS gateway provider slots in later.
package push

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
)

// Priority is an opaque wake-up urgency the sender sets on a message. The server
// never reads the payload, so it cannot know a message is (say) an SOS; the
// sending client marks it, and the server only forwards the hint to the pinger.
type Priority int

const (
	Normal Priority = iota
	High
)

// Pinger delivers a contentless wake-up to a device's push endpoint.
// Implementations must not include any payload or queue identifier.
type Pinger interface {
	Ping(ctx context.Context, endpoint string, priority Priority) error
}

// NoopPinger drops pings. It is the default when no provider is configured and
// is used by tests that do not care about wake-up.
type NoopPinger struct{}

// Ping does nothing.
func (NoopPinger) Ping(context.Context, string, Priority) error { return nil }

// UnifiedPush pings a UnifiedPush distributor (e.g. self-hosted ntfy) by POSTing
// an empty body to the device's endpoint URL. Because the ping carries nothing,
// the distributor's lack of E2E is irrelevant (PRD, Push architecture).
type UnifiedPush struct {
	Client *http.Client
}

// NewUnifiedPush returns a UnifiedPush provider using client (or a default one).
func NewUnifiedPush(client *http.Client) *UnifiedPush {
	if client == nil {
		client = http.DefaultClient
	}
	return &UnifiedPush{Client: client}
}

// Ping POSTs an empty body to endpoint. High priority is conveyed with ntfy's
// Priority header; the body stays empty regardless.
func (u *UnifiedPush) Ping(ctx context.Context, endpoint string, priority Priority) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(nil))
	if err != nil {
		return err
	}
	if priority == High {
		req.Header.Set("Priority", "high")
	}
	resp, err := u.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("push endpoint returned %d", resp.StatusCode)
	}
	return nil
}
