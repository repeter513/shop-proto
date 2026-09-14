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

func UnaryServerInterceptor(secret []byte, public ...string) grpc.UnaryServerInterceptor {
	skip := make(map[string]struct{}, len(public))
	for _, m := range public {
		skip[m] = struct{}{}
	}
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if _, ok := skip[info.FullMethod]; ok {
			return handler(ctx, req)
		}
		userID, err := userIDFromMetadata(ctx, secret)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, err.Error())
		}
		return handler(WithUserID(ctx, userID), req)
	}
}

func userIDFromMetadata(ctx context.Context, secret []byte) (int64, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return 0, errors.New("missing metadata")
	}
	vals := md.Get("authorization")
	if len(vals) == 0 {
		return 0, errors.New("missing authorization")
	}
	token := strings.TrimSpace(vals[0])
	if token == "" {
		return 0, errors.New("missing authorization")
	}
	token, ok = strings.CutPrefix(token, "Bearer ")
	if !ok {
		return 0, errors.New("invalid authorization format")
	}
	userID, err := ParseAccessUserID(token, secret)
	if err != nil {
		return 0, errors.New("invalid token")
	}
	if userID == 0 {
		return 0, errors.New("invalid token")
	}
	return userID, nil
}
