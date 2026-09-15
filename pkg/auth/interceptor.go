package auth

import (
	"context"
	"errors"
	"strings"

	authv1 "github.com/repeter513/shop-proto/gen/go/auth/v1"
	catalogv1 "github.com/repeter513/shop-proto/gen/go/catalog/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

var PublicAuth = []string{
	authv1.AuthService_RegisterUser_FullMethodName,
	authv1.AuthService_LoginUser_FullMethodName,
	authv1.AuthService_ValidateToken_FullMethodName,
	authv1.AuthService_RefreshToken_FullMethodName,
}

var PublicCatalog = []string{
	catalogv1.CatalogService_GetProduct_FullMethodName,
	catalogv1.CatalogService_ListProducts_FullMethodName,
	catalogv1.CatalogService_ListCategories_FullMethodName,
	catalogv1.CatalogService_GetStock_FullMethodName,
}

func UnaryServerInterceptor(v *Verifier, public ...string) grpc.UnaryServerInterceptor {
	skip := make(map[string]struct{}, len(public))
	for _, m := range public {
		skip[m] = struct{}{}
	}
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if _, ok := skip[info.FullMethod]; ok {
			return handler(ctx, req)
		}
		claims, err := claimsFromMetadata(ctx, v)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, err.Error())
		}
		return handler(WithAuth(ctx, claims.UserID, claims.Roles), req)
	}
}

func claimsFromMetadata(ctx context.Context, v *Verifier) (*Claims, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, errors.New("missing metadata")
	}
	vals := md.Get("authorization")
	if len(vals) == 0 {
		return nil, errors.New("missing authorization")
	}
	token := strings.TrimSpace(vals[0])
	if token == "" {
		return nil, errors.New("missing authorization")
	}
	token, ok = strings.CutPrefix(token, "Bearer ")
	if !ok {
		return nil, errors.New("invalid authorization format")
	}
	claims, err := v.ParseAccess(token)
	if err != nil || claims.UserID == 0 {
		return nil, errors.New("invalid token")
	}
	return claims, nil
}
