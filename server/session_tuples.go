package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sweetrpg/api-core.go/ratelimit"
	"github.com/sweetrpg/auth-api/auth0"
	"github.com/sweetrpg/auth-api/constants"
	"github.com/sweetrpg/auth-api/fga"
	"github.com/sweetrpg/auth-api/models"
	"github.com/sweetrpg/common.go/logging"
	"github.com/sweetrpg/common.go/util"
)

// Session tuple endpoints (PADR-0040). Users, not only the reconciler account, write the
// membership tuples for sessions they hold a relation on; auth-api mints session IDs so no caller
// can claim an ID. The caller's own bearer is the only credential (PADR-0037).

const (
	sessionObjectPrefix = "session:"
	relationGM          = "gm"
	relationCoGM        = "co_gm"
	relationPlayer      = "player"
	relationObserver    = "observer"
	relCanView          = "can_view"
	relCanEdit          = "can_edit"

	maxSessionTupleBatch = 20
	maxMintList          = 200
	maxMintMinAge        = 24 * time.Hour
	maxDeleteRounds      = 20

	tierMintUser    = "session_mint_user"
	tierMintGlobal  = "session_mint_global"
	tierSessionTups = "session_tuples"

	actionMint      = "session_mint"
	actionTuples    = "session_tuples"
	actionEnd       = "session_end"
	actionMintClose = "session_mint_close"
)

var sessionIDPattern = regexp.MustCompile(`^[0-9a-f]{24}$`)

// memberRelations are the relations the membership endpoint may write or delete. gm is never one.
var memberRelations = map[string]bool{relationCoGM: true, relationPlayer: true, relationObserver: true}

// SessionLimits are the abuse limits for the session endpoints. Defaults are PADR-0040's.
type SessionLimits struct {
	MaxOpenMints       int
	MaxSessionTuples   int
	MintsPerUserHour   int
	MintsGlobalHour    int
	TupleReqsPerMinute int
}

// SessionLimitsFromEnv reads the limits, falling back to the PADR-0040 defaults for any unset or
// non-positive value.
func SessionLimitsFromEnv() SessionLimits {
	num := func(name string, def int) int {
		if n, err := strconv.Atoi(util.GetEnv(name, "")); err == nil && n > 0 {
			return n
		}
		return def
	}
	return SessionLimits{
		MaxOpenMints:       num("MAX_OPEN_MINTS", 100),
		MaxSessionTuples:   num("MAX_SESSION_TUPLES", 200),
		MintsPerUserHour:   num("MINTS_PER_USER_HOUR", 20),
		MintsGlobalHour:    num("MINTS_GLOBAL_HOUR", 600),
		TupleReqsPerMinute: num("SESSION_TUPLE_REQS_PER_MINUTE", 120),
	}
}

// SessionTiers are the rate-limit tiers the session endpoints use, for ratelimit.New.
func SessionTiers(l SessionLimits) map[string]ratelimit.Tier {
	return map[string]ratelimit.Tier{
		tierMintUser:    {Limit: l.MintsPerUserHour, Window: 3600},
		tierMintGlobal:  {Limit: l.MintsGlobalHour, Window: 3600},
		tierSessionTups: {Limit: l.TupleReqsPerMinute, Window: 60},
	}
}

// mintStore is the session_mints collection. models.MintStore implements it.
type mintStore interface {
	Insert(ctx context.Context, m models.SessionMint) error
	CountOpen(ctx context.Context, userID string) (int64, error)
	Close(ctx context.Context, id, actor string, now time.Time) (bool, error)
	ListOpenBefore(ctx context.Context, cutoff time.Time, limit int64) ([]models.SessionMint, error)
}

// rateChecker is the Redis-backed limiter; an error means the counter store is unavailable and the
// request fails closed.
type rateChecker interface {
	Check(ctx context.Context, clientKey, tierName string) (ratelimit.Result, error)
}

// Seams for tests.
var (
	nowFunc      = func() time.Time { return time.Now().UTC() }
	newSessionID = func() (string, error) {
		b := make([]byte, 12)
		if _, err := rand.Read(b); err != nil {
			return "", err
		}
		return hex.EncodeToString(b), nil
	}
)

type sessionHandlers struct {
	fgaHandlers
	mints   mintStore
	limiter rateChecker
	limits  SessionLimits
}

// SetupSessionHandlers registers the user-scoped session endpoints and the two openfga-writer mint
// endpoints. limiter may be nil (no Redis): every endpoint then answers 503 rather than run
// unlimited.
func SetupSessionHandlers(g *gin.Engine, cache *auth0.JWKSCache, config auth0.Config, store fga.Store, mints mintStore, limiter *ratelimit.Limiter, limits SessionLimits) {
	var rc rateChecker // stays a nil interface when there is no limiter
	if limiter != nil {
		rc = limiter
	}
	registerSessionHandlers(g, fgaHandlers{store: store, cache: cache, config: config}, mints, rc, limits)
}

func registerSessionHandlers(g *gin.Engine, base fgaHandlers, mints mintStore, limiter rateChecker, limits SessionLimits) {
	ensureUserResolver()
	h := sessionHandlers{fgaHandlers: base, mints: mints, limiter: limiter, limits: limits}
	g.POST("/authz/sessions", h.mint)
	g.DELETE("/authz/sessions/:id", h.end)
	g.POST("/authz/session-tuples", h.writeSessionTuples)
	g.GET("/internal/openfga/session-mints", h.listMints)
	g.POST("/internal/openfga/session-mints/:id/close", h.closeMint)
}

type sessionCaller struct{ Subject, UserID string }

// authenticate verifies the bearer, resolves the canonical user, and refuses a user with a deny
// entry for Initiative! (PADR-0039). It writes the error response and returns ok=false on failure.
func (h sessionHandlers) authenticate(c *gin.Context) (sessionCaller, bool) {
	token := bearerToken(c)
	if token == "" {
		invalidTokenResponse(c)
		return sessionCaller{}, false
	}
	subject, err := verifyToken(c.Request.Context(), h.cache, token, h.config)
	if err != nil {
		invalidTokenResponse(c)
		return sessionCaller{}, false
	}
	p := principalFor(c.Request.Context(), subject, token)
	if p.UserID == "" {
		logging.Logger.Warn("Session request refused; canonical user unresolved", "subject", subject)
		c.JSON(http.StatusServiceUnavailable, authzErrorResponse{Error: authzUnavailable})
		return sessionCaller{}, false
	}
	denied, err := hasDenyEntry(c.Request.Context(), p, constants.InitiativeService)
	if err != nil {
		logging.Logger.Error("Failed to look up deny entry", "error", err.Error())
		c.JSON(http.StatusServiceUnavailable, authzErrorResponse{Error: authzUnavailable})
		return sessionCaller{}, false
	}
	if denied {
		c.JSON(http.StatusForbidden, authzErrorResponse{Error: "service_denied"})
		return sessionCaller{}, false
	}
	return sessionCaller{Subject: subject, UserID: p.UserID}, true
}

// allow spends one count of tier for key. No limiter, a counter-store error, or a spent budget all
// stop the request; the first two are 503, never unlimited.
func (h sessionHandlers) allow(c *gin.Context, tier, key string) bool {
	if h.limiter == nil {
		c.JSON(http.StatusServiceUnavailable, authzErrorResponse{Error: authzUnavailable})
		return false
	}
	res, err := h.limiter.Check(c.Request.Context(), key, tier)
	if err != nil {
		logging.Logger.Error("Session rate limiter unavailable; failing closed", "tier", tier, "error", err.Error())
		c.JSON(http.StatusServiceUnavailable, authzErrorResponse{Error: authzUnavailable})
		return false
	}
	if !res.Allowed {
		c.Header("Retry-After", strconv.Itoa(int(res.RetryAfter.Seconds())))
		c.JSON(http.StatusTooManyRequests, authzErrorResponse{Error: "rate_limited"})
		return false
	}
	return true
}

func userTuple(userID string) string { return userPrincipalType + userID }

// mint creates a session ID and the caller's GM tuple. The ID comes from here, never from a client.
func (h sessionHandlers) mint(c *gin.Context) {
	caller, ok := h.authenticate(c)
	if !ok || !h.allow(c, tierMintUser, caller.UserID) || !h.allow(c, tierMintGlobal, "all") {
		return
	}
	ctx := c.Request.Context()
	open, err := h.mints.CountOpen(ctx, caller.UserID)
	if err != nil {
		logging.Logger.Error("Mint count failed", "error", err.Error())
		c.JSON(http.StatusServiceUnavailable, authzErrorResponse{Error: authzUnavailable})
		return
	}
	if open >= int64(h.limits.MaxOpenMints) {
		c.JSON(http.StatusTooManyRequests, authzErrorResponse{Error: "mint_cap"})
		return
	}
	id, err := newSessionID()
	if err != nil {
		c.JSON(http.StatusInternalServerError, authzErrorResponse{Error: "query_failed"})
		return
	}
	gm := fga.Tuple{User: userTuple(caller.UserID), Relation: relationGM, Object: sessionObjectPrefix + id}
	now := nowFunc()
	mint := models.SessionMint{ID: id, UserID: caller.UserID, CreatedAt: now, CreatedBy: caller.UserID, UpdatedAt: now, UpdatedBy: caller.UserID}
	_, err = auditedWrite(ctx, caller.Subject, actionMint, gm.Object, "user="+caller.UserID+"; "+auditDetail(tupleWriteRequest{Writes: []fga.Tuple{gm}}),
		func(ctx context.Context) (int, error) {
			if err := h.mints.Insert(ctx, mint); err != nil {
				return 0, err
			}
			if err := h.store.Write(ctx, []fga.Tuple{gm}, nil); err != nil {
				if _, cerr := h.mints.Close(ctx, id, caller.UserID, nowFunc()); cerr != nil {
					logging.Logger.Warn("Could not close mint after a failed tuple write", "mint", id, "error", cerr.Error())
				}
				return 0, err
			}
			return http.StatusCreated, nil
		})
	if err != nil {
		logging.Logger.Error("Session mint failed", "error", err.Error())
		c.JSON(http.StatusServiceUnavailable, authzErrorResponse{Error: authzUnavailable})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"session_id": id})
}

// end deletes every tuple on a session and closes its mint. Only the GM may.
func (h sessionHandlers) end(c *gin.Context) {
	caller, ok := h.authenticate(c)
	if !ok {
		return
	}
	id := c.Param("id")
	if !sessionIDPattern.MatchString(id) {
		c.JSON(http.StatusBadRequest, authzErrorResponse{Error: "invalid_request"})
		return
	}
	if !h.allow(c, tierSessionTups, caller.UserID) {
		return
	}
	object := sessionObjectPrefix + id
	allowed, err := h.store.Check(c.Request.Context(), fga.Tuple{User: userTuple(caller.UserID), Relation: relationGM, Object: object})
	if err != nil {
		logging.Logger.Error("OpenFGA check failed", "object", object, "error", err.Error())
		c.JSON(http.StatusServiceUnavailable, authzErrorResponse{Error: authzUnavailable})
		return
	}
	if !allowed {
		c.JSON(http.StatusForbidden, authzErrorResponse{Error: "forbidden"})
		return
	}
	if err := h.removeSession(c.Request.Context(), caller.Subject, caller.UserID, actionEnd, id); err != nil {
		c.JSON(http.StatusServiceUnavailable, authzErrorResponse{Error: authzUnavailable})
		return
	}
	c.Status(http.StatusNoContent)
}

// removeSession is the audited removal of a session's tuples and its mint, shared by the GM's end
// and the reconciler's garbage-collection close.
func (h sessionHandlers) removeSession(ctx context.Context, subject, actor, action, id string) error {
	object := sessionObjectPrefix + id
	_, err := auditedWrite(ctx, subject, action, object, "user="+actor+"; delete all tuples on "+object, func(ctx context.Context) (int, error) {
		if err := deleteAllTuples(ctx, h.store, object); err != nil {
			return 0, err
		}
		if _, err := h.mints.Close(ctx, id, actor, nowFunc()); err != nil {
			return 0, err
		}
		return http.StatusOK, nil
	})
	if err != nil {
		logging.Logger.Error("Session removal failed", "object", object, "error", err.Error())
	}
	return err
}

// deleteAllTuples removes every tuple on object, a page at a time. Deleting a missing tuple is
// ignored by the store, so a retry after a partial run is safe.
func deleteAllTuples(ctx context.Context, store fga.Store, object string) error {
	for range maxDeleteRounds {
		page, _, err := store.Read(ctx, object, maxTuplePage, "")
		if err != nil {
			return err
		}
		if len(page) == 0 {
			return nil
		}
		if err := store.Write(ctx, nil, page); err != nil {
			return err
		}
	}
	return errors.New("session still has tuples after the delete rounds")
}

// countTuples counts the tuples on object, stopping once it passes limit.
func countTuples(ctx context.Context, store fga.Store, object string, limit int) (int, error) {
	total, token := 0, ""
	for total <= limit {
		page, next, err := store.Read(ctx, object, maxTuplePage, token)
		if err != nil {
			return 0, err
		}
		total += len(page)
		if next == "" {
			break
		}
		token = next
	}
	return total, nil
}

type sessionTuple struct {
	User     string `json:"user"`
	Relation string `json:"relation"`
}

type sessionTuplesRequest struct {
	SessionID string         `json:"session_id"`
	Writes    []sessionTuple `json:"writes"`
	Deletes   []sessionTuple `json:"deletes"`
}

// requiredRelation is what the caller must hold on the session for this change (PADR-0040 rule
// table): can_view to delete only their own tuple (leaving), gm for any co_gm tuple, can_edit
// otherwise. ok is false when a tuple is malformed or uses a relation this endpoint never writes.
func requiredRelation(req sessionTuplesRequest, callerUser string) (rel string, ok bool) {
	n := len(req.Writes) + len(req.Deletes)
	if n == 0 || n > maxSessionTupleBatch {
		return "", false
	}
	needGM, ownOnly := false, len(req.Writes) == 0
	for _, t := range append(append([]sessionTuple{}, req.Writes...), req.Deletes...) {
		if !validUser(t.User) || !memberRelations[t.Relation] {
			return "", false
		}
		needGM = needGM || t.Relation == relationCoGM
		ownOnly = ownOnly && t.User == userTuple(callerUser)
	}
	switch {
	case ownOnly:
		return relCanView, true
	case needGM:
		return relationGM, true
	}
	return relCanEdit, true
}

func objectTuples(object string, ts []sessionTuple) []fga.Tuple {
	out := make([]fga.Tuple, 0, len(ts))
	for _, t := range ts {
		out = append(out, fga.Tuple{User: t.User, Relation: t.Relation, Object: object})
	}
	return out
}

// writeSessionTuples applies membership tuple changes on one session after checking the caller's
// own relation on it. The object is always session:<id>, so no other object type is reachable.
// The tuples are necessary but not sufficient: initiative-api still requires a live Mongo
// membership record, and its reconciler removes tuples Mongo does not back.
func (h sessionHandlers) writeSessionTuples(c *gin.Context) {
	caller, ok := h.authenticate(c)
	if !ok {
		return
	}
	var req sessionTuplesRequest
	if err := c.ShouldBindJSON(&req); err != nil || !sessionIDPattern.MatchString(req.SessionID) {
		c.JSON(http.StatusBadRequest, authzErrorResponse{Error: "invalid_request"})
		return
	}
	need, valid := requiredRelation(req, caller.UserID)
	if !valid {
		c.JSON(http.StatusBadRequest, authzErrorResponse{Error: "invalid_request"})
		return
	}
	if !h.allow(c, tierSessionTups, caller.UserID) {
		return
	}
	ctx, object := c.Request.Context(), sessionObjectPrefix+req.SessionID
	held, err := h.store.Check(ctx, fga.Tuple{User: userTuple(caller.UserID), Relation: need, Object: object})
	if err != nil {
		logging.Logger.Error("OpenFGA check failed", "object", object, "error", err.Error())
		c.JSON(http.StatusServiceUnavailable, authzErrorResponse{Error: authzUnavailable})
		return
	}
	if !held {
		c.JSON(http.StatusForbidden, authzErrorResponse{Error: "forbidden"})
		return
	}
	writes, deletes := objectTuples(object, req.Writes), objectTuples(object, req.Deletes)
	if len(writes) > 0 {
		current, err := countTuples(ctx, h.store, object, h.limits.MaxSessionTuples)
		if err != nil {
			c.JSON(http.StatusServiceUnavailable, authzErrorResponse{Error: authzUnavailable})
			return
		}
		if current+len(writes)-len(deletes) > h.limits.MaxSessionTuples {
			c.JSON(http.StatusConflict, authzErrorResponse{Error: "session_full"})
			return
		}
	}
	detail := fmt.Sprintf("user=%s; %s", caller.UserID, auditDetail(tupleWriteRequest{Writes: writes, Deletes: deletes}))
	if _, err := auditedWrite(ctx, caller.Subject, actionTuples, object, detail, func(ctx context.Context) (int, error) {
		return http.StatusOK, h.store.Write(ctx, writes, deletes)
	}); err != nil {
		logging.Logger.Error("Session tuple write failed", "object", object, "error", err.Error())
		if errors.Is(err, fga.ErrInvalid) {
			c.JSON(http.StatusBadRequest, authzErrorResponse{Error: "invalid_tuples"})
			return
		}
		c.JSON(http.StatusServiceUnavailable, authzErrorResponse{Error: authzUnavailable})
		return
	}
	c.JSON(http.StatusOK, gin.H{"writes": len(writes), "deletes": len(deletes)})
}

// listMints returns open mints at least min_age old by auth-api's own clock, for the reconciler's
// garbage collection. It requires openfga-writer.
func (h sessionHandlers) listMints(c *gin.Context) {
	if _, ok := h.requireWriter(c); !ok {
		return
	}
	age, err := time.ParseDuration(c.Query("min_age"))
	if err != nil || age < 0 || age > maxMintMinAge {
		c.JSON(http.StatusBadRequest, authzErrorResponse{Error: "invalid_request"})
		return
	}
	limit := int64(100)
	if raw := c.Query("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > maxMintList {
			c.JSON(http.StatusBadRequest, authzErrorResponse{Error: "invalid_request"})
			return
		}
		limit = int64(n)
	}
	mints, err := h.mints.ListOpenBefore(c.Request.Context(), nowFunc().Add(-age), limit)
	if err != nil {
		logging.Logger.Error("Mint list failed", "error", err.Error())
		c.JSON(http.StatusServiceUnavailable, authzErrorResponse{Error: authzUnavailable})
		return
	}
	if mints == nil {
		mints = []models.SessionMint{}
	}
	c.JSON(http.StatusOK, gin.H{"mints": mints})
}

// closeMint deletes every tuple on a minted session and closes its mint. The reconciler calls it
// for a mint whose session Mongo does not have (or has deleted). It requires openfga-writer.
func (h sessionHandlers) closeMint(c *gin.Context) {
	subject, ok := h.requireWriter(c)
	if !ok {
		return
	}
	id := c.Param("id")
	if !sessionIDPattern.MatchString(id) {
		c.JSON(http.StatusBadRequest, authzErrorResponse{Error: "invalid_request"})
		return
	}
	if err := h.removeSession(c.Request.Context(), subject, subject, actionMintClose, id); err != nil {
		c.JSON(http.StatusServiceUnavailable, authzErrorResponse{Error: authzUnavailable})
		return
	}
	c.Status(http.StatusNoContent)
}
