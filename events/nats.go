package events

import (
	"context"
	"fmt"
	"os"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// NATS publishes to JetStream, where the AUTH_EVENTS stream captures auth.events.>.
type NATS struct {
	conn *nats.Conn
	js   jetstream.JetStream
}

// ConnectNATS dials url with NATS_CREDS or NATS_USER/NATS_PASSWORD from the environment.
func ConnectNATS(url string) (*NATS, error) {
	opts := []nats.Option{nats.Name("auth-api"), nats.MaxReconnects(-1)}
	if creds := os.Getenv("NATS_CREDS"); creds != "" {
		opts = append(opts, nats.UserCredentials(creds))
	} else if user := os.Getenv("NATS_USER"); user != "" {
		opts = append(opts, nats.UserInfo(user, os.Getenv("NATS_PASSWORD")))
	}
	conn, err := nats.Connect(url, opts...)
	if err != nil {
		return nil, fmt.Errorf("connect to NATS: %w", err)
	}
	js, err := jetstream.New(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("create JetStream context: %w", err)
	}
	return &NATS{conn: conn, js: js}, nil
}

// Publish sends body and waits for the stream's acknowledgement. msgID is the dedupe key.
func (n *NATS) Publish(ctx context.Context, subject, msgID string, body []byte) error {
	_, err := n.js.Publish(ctx, subject, body, jetstream.WithMsgID(msgID))
	return err
}

// Close drains the connection.
func (n *NATS) Close() { _ = n.conn.Drain() }
