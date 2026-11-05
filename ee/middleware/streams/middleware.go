package streams

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/internal/middleware"
	"github.com/TykTechnologies/tyk/internal/model"
)

// Middleware implements a streaming middleware.
type Middleware struct {
	Spec *APISpec
	Gw   Gateway

	base BaseMiddleware

	createStreamManagerLock sync.Mutex
	StreamManagerCache      sync.Map // Map of payload hash to Manager

	ctx              context.Context
	cancel           context.CancelFunc
	allowedUnsafe    []string
	defaultManager   *Manager
	analyticsFactory StreamAnalyticsFactory
}

// Middleware implements model.Middleware.
var _ model.Middleware = &Middleware{}

// NewMiddleware returns a new instance of Middleware.
func NewMiddleware(gw Gateway, mw BaseMiddleware, spec *APISpec, analyticsFactory StreamAnalyticsFactory) *Middleware {
	return &Middleware{
		base:             mw,
		Gw:               gw,
		Spec:             spec,
		analyticsFactory: analyticsFactory,
	}
}

// Logger returns a logger with middleware filled out.
func (s *Middleware) Logger() *logrus.Entry {
	return s.base.Logger().WithField("mw", s.Name())
}

// Name returns the name for the middleware.
func (s *Middleware) Name() string {
	return "StreamingMiddleware"
}

// EnabledForSpec checks if streaming is enabled on the config.
func (s *Middleware) EnabledForSpec() bool {
	s.Logger().Debug("Checking if streaming is enabled")

	streamingConfig := s.Gw.GetConfig().Streaming
	s.Logger().Debugf("Streaming config: %+v", streamingConfig)

	if streamingConfig.Enabled {
		s.Logger().Debug("Streaming is enabled in the config")
		s.allowedUnsafe = streamingConfig.AllowUnsafe
		s.Logger().Debugf("Allowed unsafe components: %v", s.allowedUnsafe)

		config := s.getStreamsConfig(nil)
		GlobalStreamCounter.Add(int64(len(config.Streams)))
		s.Logger().Debug("Total streams count: ", len(config.Streams))

		return len(config.Streams) != 0
	}

	s.Logger().Debug("Streaming is not enabled in the config")
	return false
}

// Init initializes the middleware
func (s *Middleware) Init() {
	s.Logger().Debug("Initializing Middleware")
	s.ctx, s.cancel = context.WithCancel(context.Background())

	s.Logger().Debug("Initializing default stream manager")
	s.defaultManager = s.CreateStreamManager(nil)

	s.Logger().Debug("Initializing stream analytics factory")
	if s.analyticsFactory == nil {
		s.SetAnalyticsFactory(&NoopStreamAnalyticsFactory{})
	} else {
		s.SetAnalyticsFactory(s.analyticsFactory)
	}

	// Start garbage collection routine
	go func() {
		ticker := time.NewTicker(StreamGCInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				s.GC()
			case <-s.ctx.Done():
				return
			}
		}
	}()
}

// CreateStreamManager creates or retrieves a stream manager based on the request.
func (s *Middleware) CreateStreamManager(r *http.Request) *Manager {
	streamsConfig := s.getStreamsConfig(r)
	configJSON, _ := json.Marshal(streamsConfig)
	cacheKey := fmt.Sprintf("%x", sha256.Sum256(configJSON))

	s.createStreamManagerLock.Lock()
	defer s.createStreamManagerLock.Unlock()

	s.Logger().Debug("Attempting to load stream manager from cache")
	s.Logger().Debugf("Cache key: %s", cacheKey)
	if cachedManager, found := s.StreamManagerCache.Load(cacheKey); found {
		s.Logger().Debug("Found cached stream manager")
		return cachedManager.(*Manager)
	}

	newManager := &Manager{
		muxer:            mux.NewRouter(),
		mw:               s,
		dryRun:           r == nil,
		activityCounter:  atomic.Int32{},
		analyticsFactory: &NoopStreamAnalyticsFactory{},
	}
	newManager.initStreams(r, streamsConfig)

	if r != nil {
		s.StreamManagerCache.Store(cacheKey, newManager)
	}
	return newManager
}

// GC removes inactive stream managers.
func (s *Middleware) GC() {
	s.Logger().Debug("Starting garbage collection for inactive stream managers")

	s.StreamManagerCache.Range(func(key, value interface{}) bool {
		manager := value.(*Manager)
		if manager == s.defaultManager {
			return true
		}

		if manager.activityCounter.Load() <= 0 {
			s.Logger().Infof("Removing inactive stream manager: %v", key)
			manager.streams.Range(func(streamKey, streamValue interface{}) bool {
				streamID := streamKey.(string)
				err := manager.removeStream(streamID)
				if err != nil {
					s.Logger().WithError(err).Errorf("Error removing stream %s", streamID)
				}
				return true
			})
			s.StreamManagerCache.Delete(key)
		}

		return true
	})
}

func (s *Middleware) getStreamsConfig(r *http.Request) *StreamsConfig {
	config := &StreamsConfig{Streams: make(map[string]any)}
	if !s.Spec.IsOAS {
		return config
	}

	// After Initialize() is called on OAS, the extension is converted to *XTykStreaming.
	// Get the typed struct which contains the Streams field.
	xTykStreaming := s.Spec.OAS.GetTykStreamingExtension()
	if xTykStreaming != nil && xTykStreaming.Streams != nil {
		s.processStreamsConfig(r, xTykStreaming.Streams, config)
	}

	return config
}

func (s *Middleware) processStreamsConfig(r *http.Request, streams map[string]any, config *StreamsConfig) {
	for streamID, stream := range streams {
		if r == nil {
			s.Logger().Debugf("No request available to replace variables in stream config for %s", streamID)
		} else {
			s.Logger().Debugf("Stream config for %s: %v", streamID, stream)
			replacedStream, err := s.replaceStreamVariables(r, stream)
			if err != nil {
				s.Logger().Errorf("Failed to replace variables in stream config: %v", err)
				continue
			}
			s.Logger().Debugf("Stream config for %s after variable replacement: %v", streamID, replacedStream)
			stream = replacedStream
		}
		config.Streams[streamID] = stream
	}
}

// requestVariableMatch matches request-derived variables ($tyk_context.* and $tyk_meta.*).
var requestVariableMatch = regexp.MustCompile(`\$tyk_(?:context|meta)\.[A-Za-z0-9_\-\.]+`)

// replaceStreamVariables returns a deep copy of the stream config with Tyk variables
// replaced inside string leaf values only. Substituted values are treated as data and
// are never re-parsed, so they cannot alter the structure of the stream config.
func (s *Middleware) replaceStreamVariables(r *http.Request, stream any) (map[string]any, error) {
	marshaledStream, err := json.Marshal(stream)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal stream config: %w", err)
	}

	var streamCopy map[string]any
	if err := json.Unmarshal(marshaledStream, &streamCopy); err != nil {
		return nil, fmt.Errorf("failed to unmarshal stream config: %w", err)
	}

	for key, value := range streamCopy {
		streamCopy[key] = s.replaceVariablesInValue(r, value)
	}

	return streamCopy, nil
}

func (s *Middleware) replaceVariablesInValue(r *http.Request, value any) any {
	switch v := value.(type) {
	case map[string]any:
		for key, item := range v {
			v[key] = s.replaceVariablesInValue(r, item)
		}
		return v
	case []any:
		for i, item := range v {
			v[i] = s.replaceVariablesInValue(r, item)
		}
		return v
	case string:
		return s.replaceVariablesInString(r, v)
	default:
		return v
	}
}

// replaceVariablesInString resolves operator-defined references (secrets, env, KV) in the
// literal parts of a string, and URL-escapes every request-derived variable value
// unconditionally.
func (s *Middleware) replaceVariablesInString(r *http.Request, in string) string {
	var out strings.Builder
	last := 0
	for _, loc := range requestVariableMatch.FindAllStringIndex(in, -1) {
		out.WriteString(s.Gw.ReplaceTykVariables(r, in[last:loc[0]], true))
		rawValue := s.Gw.ReplaceTykVariables(r, in[loc[0]:loc[1]], false)
		out.WriteString(url.QueryEscape(rawValue))
		last = loc[1]
	}
	out.WriteString(s.Gw.ReplaceTykVariables(r, in[last:], true))
	return out.String()
}

// ProcessRequest will handle the streaming functionality.
func (s *Middleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	strippedPath := s.Spec.StripListenPath(r.URL.Path)
	if !s.defaultManager.hasPath(strippedPath) {
		s.Logger().Debugf("Path not found: %s", strippedPath)
		return errors.New("not found"), http.StatusNotFound
	}

	s.Logger().Debugf("Processing request: %s, %s", r.URL.Path, strippedPath)

	newRequest := &http.Request{
		Method: r.Method,
		URL:    &url.URL{Scheme: r.URL.Scheme, Host: r.URL.Host, Path: strippedPath},
	}

	if !s.defaultManager.muxer.Match(newRequest, &mux.RouteMatch{}) {
		return nil, http.StatusOK
	}

	var match mux.RouteMatch
	streamManager := s.CreateStreamManager(r)
	streamManager.SetAnalyticsFactory(s.analyticsFactory)
	streamManager.routeLock.Lock()
	streamManager.muxer.Match(newRequest, &match)
	streamManager.routeLock.Unlock()

	// direct Bento handler
	handler, ok := match.Handler.(http.HandlerFunc)
	if !ok {
		return errors.New("invalid route handler"), http.StatusInternalServerError
	}

	streamManager.activityCounter.Add(1)
	defer streamManager.activityCounter.Add(-1)

	handler.ServeHTTP(w, r)

	return nil, middleware.StatusRespond
}

func (s *Middleware) resetStream(streamValue any) {
	if stream, ok := streamValue.(*Stream); ok {
		if err := stream.Reset(); err != nil {
			s.Logger().WithError(err).Error("Failed to reset stream")
		}
	}
}

// Unload closes and remove active streams. This method is called when the API is removed.
func (s *Middleware) Unload() {
	s.Logger().Debugf("Unloading streaming middleware %s", s.Spec.Name)

	totalStreams := 0
	s.cancel()

	// Reset cached streams and stop the underlying Bento instances
	s.StreamManagerCache.Range(func(_, value interface{}) bool {
		manager, ok := value.(*Manager)
		if !ok {
			return true
		}
		manager.streams.Range(func(_, streamValue interface{}) bool {
			totalStreams++
			s.resetStream(streamValue)
			return true // continue iterating
		})
		return true
	})

	// Finally, reset the default manager and stop the underlying Bento instance
	s.defaultManager.streams.Range(func(_, streamValue interface{}) bool {
		totalStreams++
		s.resetStream(streamValue)
		return true // continue iterating
	})

	GlobalStreamCounter.Add(-int64(totalStreams))
	s.StreamManagerCache = sync.Map{}
	s.Logger().Info("All streams successfully removed")
}

func (s *Middleware) SetAnalyticsFactory(factory StreamAnalyticsFactory) {
	if factory == nil {
		factory = &NoopStreamAnalyticsFactory{}
	}
	s.analyticsFactory = factory
	s.defaultManager.SetAnalyticsFactory(factory)
}

func (s *Middleware) GetStreamManager() *Manager {
	return s.defaultManager
}
