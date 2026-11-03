package streams

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"

	_ "github.com/TykTechnologies/tyk/internal/portal"
	_ "github.com/warpstreamlabs/bento/public/components/all"
	"github.com/warpstreamlabs/bento/public/service"
)

// Stream is a wrapper around stream
type Stream struct {
	allowedUnsafe []string
	streamConfig  string
	stream        *service.Stream
	logger        *logrus.Entry
}

// NewStream creates a new stream without initializing it
func NewStream(allowUnsafe []string, logger *logrus.Entry) *Stream {
	if len(allowUnsafe) > 0 {
		logger.Warnf("Allowing unsafe components: %v", allowUnsafe)
	}

	return &Stream{
		logger:        logger,
		allowedUnsafe: allowUnsafe,
	}
}

// Start loads up the configuration and starts the stream. Non-blocking
func (s *Stream) Start(config map[string]interface{}, mux service.HTTPMultiplexer) error {
	s.logger.Debugf("Starting stream")

	configPayload, err := yaml.Marshal(config)
	if err != nil {
		s.logger.Errorf("Failed to marshal config: %v", err)
		return err
	}

	s.logger.Debugf("Building new stream")
	env, err := s.newEnvironment()
	if err != nil {
		s.logger.Errorf("Failed to create stream environment: %v", err)
		return err
	}
	builder := env.NewStreamBuilder()
	handler := slog.NewJSONHandler(newBentoLogAdapter(s.logger), nil)
	builder.SetLogger(slog.New(handler))

	err = builder.SetYAML(string(configPayload))
	if err != nil {
		s.logger.Errorf("Failed to set YAML: %v", err)
		return err
	}

	if mux != nil {
		builder.SetHTTPMux(mux)
	}

	stream, err := builder.Build()
	if err != nil {
		s.logger.Errorf("Failed to build stream: %v", err)
		return err
	}

	s.streamConfig = string(configPayload)
	s.stream = stream

	s.logger.Debugf("Stream built successfully, starting it")

	errChan := make(chan error, 1)
	go func() {
		s.logger.Infof("Starting stream")
		errChan <- stream.Run(context.Background())
	}()

	select {
	case err := <-errChan:
		if err != nil {
			s.logger.Errorf("Stream encountered an error: %v", err)
			return err
		}
	case <-time.After(100 * time.Millisecond):
		// If no error after a short delay, assume stream started successfully
	}

	s.logger.Debugf("Stream started successfully")
	return nil
}

// Stop cleans up the stream
func (s *Stream) Stop() error {
	s.logger.Printf("Stopping stream")

	if s.stream == nil {
		s.logger.Printf("No active stream to stop")
		return nil
	}

	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errChan := make(chan error, 1)
	go func() {
		errChan <- s.stream.Stop(stopCtx)
	}()

	select {
	case err := <-errChan:
		if err != nil {
			s.logger.Printf("Error stopping stream: %v", err)
		} else {
			s.logger.Printf("Stream stopped successfully")
		}
	case <-stopCtx.Done():
		s.logger.Printf("Timeout while stopping stream")
	}

	s.streamConfig = ""
	s.stream = nil

	return nil
}

// GetConfig returns the configuration of the stream
func (s *Stream) GetConfig() string {
	return s.streamConfig
}

// Reset stops the stream
func (s *Stream) Reset() error {
	return s.Stop()
}

// unsafeComponents lists Bento components that are disabled unless explicitly
// allowed via streaming.allow_unsafe. A listed name is disabled for every
// component kind (input, processor, output, cache) that registers it.
var unsafeComponents = []string{
	"command", "csv", "dynamic", "file", "inproc", "socket", "socket_server", "stdin", "subprocess", "wasm",
}

// newEnvironment returns a Bento environment in which every unsafe component
// that is not allowlisted is replaced by a stub that fails linting and
// construction. Enforcement happens in Bento's own config parser, so it applies
// wherever the component appears (lists, brokers, resources, `type:` fields).
func (s *Stream) newEnvironment() (*service.Environment, error) {
	env := service.NewEnvironment()

	for _, name := range s.blockedComponents() {
		reason := fmt.Sprintf("component '%s' is disabled; add it to streaming.allow_unsafe to enable it", name)
		spec := service.NewConfigSpec().
			Summary(reason).
			LintRule(fmt.Sprintf("root = %q", reason))
		disabled := errors.New(reason)

		if _, ok := env.GetInputConfig(name); ok {
			if err := env.RegisterInput(name, spec, func(*service.ParsedConfig, *service.Resources) (service.Input, error) {
				return nil, disabled
			}); err != nil {
				return nil, err
			}
		}
		if _, ok := env.GetProcessorConfig(name); ok {
			if err := env.RegisterProcessor(name, spec, func(*service.ParsedConfig, *service.Resources) (service.Processor, error) {
				return nil, disabled
			}); err != nil {
				return nil, err
			}
		}
		if _, ok := env.GetOutputConfig(name); ok {
			if err := env.RegisterOutput(name, spec, func(*service.ParsedConfig, *service.Resources) (service.Output, int, error) {
				return nil, 0, disabled
			}); err != nil {
				return nil, err
			}
		}
		if _, ok := env.GetCacheConfig(name); ok {
			if err := env.RegisterCache(name, spec, func(*service.ParsedConfig, *service.Resources) (service.Cache, error) {
				return nil, disabled
			}); err != nil {
				return nil, err
			}
		}
	}

	return env, nil
}

func (s *Stream) blockedComponents() []string {
	blocked := make([]string, 0, len(unsafeComponents))
	for _, component := range unsafeComponents {
		if !slices.Contains(s.allowedUnsafe, component) {
			blocked = append(blocked, component)
		}
	}
	return blocked
}
