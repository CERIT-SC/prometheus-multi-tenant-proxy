package proxy

import (
	"context"
	"log"
	"net/http"
	"strings"
)

type key int

// Auth implements an authentication middleware
type Auth interface {
	// IsAuthorized authenticates a request and returns the list of namespaces the user has access to
	IsAuthorized(r *http.Request) (bool, []string, map[string][]string, []string, []string)
	// WriteUnauthorisedResponse writes an HTTP response in case the user is forbidden
	WriteUnauthorisedResponse(w http.ResponseWriter)
	// Load loads or reloads the configuration
	Load() bool
}

// AuthHandler returns au authentication middleware handler
func AuthHandler(auth Auth, whitelist []string, handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if whitelist != nil && !isInWhitelist(r.URL.Path, whitelist) {
			log.Printf("Unauthorized due to whitelist")
			auth.WriteUnauthorisedResponse(w)
			return
		}

		authorized, namespaces, labels, whitelisted, exported := auth.IsAuthorized(r)
		if !authorized {
			log.Printf("Unauthorized due to namespace/labels")
			auth.WriteUnauthorisedResponse(w)
			return
		}
		if len(namespaces) == 0 && len(labels) == 0 {
			log.Printf("[WARNING] No namespaces or labels found for request")
			auth.WriteUnauthorisedResponse(w)
			return
		}
		ctx := context.WithValue(r.Context(), Namespaces, namespaces)
		ctx = context.WithValue(ctx, Labels, labels)
		ctx = context.WithValue(ctx, MetricsWhitelist, whitelisted)
		ctx = context.WithValue(ctx, ExportedMetrics, exported)
		handler(w, r.WithContext(ctx))
	}
}

func isInWhitelist(requestPath string, whitelist []string) bool {
	allowed := false
	for _, endpoint := range whitelist {
		allowed = allowed || strings.HasSuffix(requestPath, endpoint)
	}
	return allowed
}
