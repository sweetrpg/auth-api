package models

import "go.mongodb.org/mongo-driver/bson"

// Principal is who a role or deny entry applies to: a login (Auth0 subject) and, when known, the
// canonical user that login belongs to. Rows are matched by either, so a role granted to the
// person reaches every linked login, and a row written before user IDs existed still matches
// through its subject.
type Principal struct {
	Subject string
	UserID  string
}

// filter matches the principal's rows by user_id or subject.
func (p Principal) filter() bson.D {
	if p.UserID == "" {
		return bson.D{{Key: "subject", Value: p.Subject}}
	}
	return bson.D{{Key: "$or", Value: bson.A{
		bson.D{{Key: "user_id", Value: p.UserID}},
		bson.D{{Key: "subject", Value: p.Subject}},
	}}}
}

// with narrows the principal filter by one more field.
func (p Principal) with(key string, value any) bson.D {
	return bson.D{{Key: "$and", Value: bson.A{p.filter(), bson.D{{Key: key, Value: value}}}}}
}
