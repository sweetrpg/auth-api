package models

import (
	"context"
	"errors"
	"time"

	"github.com/sweetrpg/auth-api/constants"
	"github.com/sweetrpg/mongodb.go/database"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// ClosedMintRetention is how long a closed mint record is kept before the TTL index removes it. The
// audit log keeps the history (PADR-0040).
const ClosedMintRetention = 30 * 24 * time.Hour

// SessionMint records that auth-api minted a session ID for a user and wrote the GM tuple. It is
// open until the session is ended or garbage collected. ClosedAt is absent while open, which the
// TTL index relies on: only a closed record carries the date.
type SessionMint struct {
	ID        string     `bson:"_id" json:"id"`
	UserID    string     `bson:"user_id" json:"user_id"`
	CreatedAt time.Time  `bson:"created_at" json:"created_at"`
	CreatedBy string     `bson:"created_by" json:"-"`
	UpdatedAt time.Time  `bson:"updated_at" json:"-"`
	UpdatedBy string     `bson:"updated_by" json:"-"`
	ClosedAt  *time.Time `bson:"closed_at,omitempty" json:"-"`
}

// MintStore is the Mongo-backed store of session mints.
type MintStore struct{}

func mintColl() *mongo.Collection {
	return database.Db.Collection(constants.SessionMintsCollection)
}

// EnsureSessionMintIndexes creates the indexes the mint queries and the retention rule need.
func EnsureSessionMintIndexes(ctx context.Context) error {
	_, err := mintColl().Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "user_id", Value: 1}, {Key: "closed_at", Value: 1}}},
		{Keys: bson.D{{Key: "closed_at", Value: 1}, {Key: "created_at", Value: 1}}},
		{
			Keys:    bson.D{{Key: "closed_at", Value: 1}},
			Options: options.Index().SetExpireAfterSeconds(int32(ClosedMintRetention / time.Second)).SetName("closed_at_ttl"),
		},
	})
	return err
}

// Insert stores a new open mint.
func (MintStore) Insert(ctx context.Context, m SessionMint) error {
	_, err := mintColl().InsertOne(ctx, m)
	return err
}

// CountOpen returns how many open mints userID holds.
func (MintStore) CountOpen(ctx context.Context, userID string) (int64, error) {
	return mintColl().CountDocuments(ctx, bson.D{{Key: "user_id", Value: userID}, {Key: "closed_at", Value: nil}})
}

// Close ends an open mint. It reports whether this call closed it: the match requires closed_at to
// be absent, so closing twice (or racing a garbage collection) is a no-op for the second caller.
func (MintStore) Close(ctx context.Context, id, actor string, now time.Time) (bool, error) {
	res := mintColl().FindOneAndUpdate(ctx,
		bson.D{{Key: "_id", Value: id}, {Key: "closed_at", Value: nil}},
		bson.D{{Key: "$set", Value: bson.D{{Key: "closed_at", Value: now}, {Key: "updated_at", Value: now}, {Key: "updated_by", Value: actor}}}})
	if err := res.Err(); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// ListOpenBefore returns open mints created at or before cutoff, oldest first, at most limit.
func (MintStore) ListOpenBefore(ctx context.Context, cutoff time.Time, limit int64) ([]SessionMint, error) {
	cur, err := mintColl().Find(ctx,
		bson.D{{Key: "closed_at", Value: nil}, {Key: "created_at", Value: bson.D{{Key: "$lte", Value: cutoff}}}},
		options.Find().SetSort(bson.D{{Key: "created_at", Value: 1}}).SetLimit(limit))
	if err != nil {
		return nil, err
	}
	var out []SessionMint
	if err := cur.All(ctx, &out); err != nil {
		return nil, err
	}
	return out, nil
}
