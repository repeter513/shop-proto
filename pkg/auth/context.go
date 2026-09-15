package auth

import (
	"context"
	"errors"
)

type ctxKey struct{}

type authCtx struct {
	userID int64
	roles  []string
}

var ErrUserIDMissing = errors.New("user id missing from context")

func WithUserID(ctx context.Context, userID int64) context.Context {
	return WithAuth(ctx, userID, nil)
}

func WithAuth(ctx context.Context, userID int64, roles []string) context.Context {
	return context.WithValue(ctx, ctxKey{}, authCtx{userID: userID, roles: roles})
}

func UserIDFromContext(ctx context.Context) (int64, error) {
	switch v := ctx.Value(ctxKey{}).(type) {
	case authCtx:
		if v.userID == 0 {
			return 0, ErrUserIDMissing
		}
		return v.userID, nil
	case int64:
		if v == 0 {
			return 0, ErrUserIDMissing
		}
		return v, nil
	default:
		return 0, ErrUserIDMissing
	}
}
func RolesFromContext(ctx context.Context) []string {
	if v, ok := ctx.Value(ctxKey{}).(authCtx); ok {
		return v.roles
	}
	return nil
}
func HasRole(ctx context.Context, role string) bool {
	for _, r := range RolesFromContext(ctx) {
		if r == role {
			return true
		}
	}
	return false
}
