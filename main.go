package main

import (
	"encoding/json"
	"errors"
	"net/rpc"
	"strings"
	"time"

	"github.com/tidwall/gjson"
	"github.com/v1Flows/runner/pkg/executions"
	"github.com/v1Flows/runner/pkg/plugins"

	af_models "github.com/v1Flows/alertFlow/services/backend/pkg/models"
	"github.com/v1Flows/shared-library/pkg/models"

	"github.com/hashicorp/go-plugin"
)

type Receiver struct {
	Receiver string `json:"receiver"`
}

type IncomingFlow struct {
	Flow af_models.Flows `json:"flow"`
}

// Plugin is an implementation of the Plugin interface
type Plugin struct{}

func (p *Plugin) ExecuteTask(request plugins.ExecuteTaskRequest) (plugins.Response, error) {
	if request.Platform != "alertflow" {
		return plugins.Response{
			Success: false,
		}, errors.New("platform not supported")
	}

	err := executions.UpdateStep(request.Config, request.Execution.ID.String(), models.ExecutionSteps{
		ID: request.Step.ID,
		Messages: []models.Message{
			{
				Title: "Pattern Check",
				Lines: []string{"Checking for patterns"},
			},
		},
		Status:    "running",
		StartedAt: time.Now(),
	}, request.Platform)
	if err != nil {
		return plugins.Response{}, err
	}

	var flow IncomingFlow
	err = json.Unmarshal(request.FlowBytes, &flow)
	if err != nil {
		return plugins.Response{
			Success: false,
		}, err
	}

	// end if there are no patterns
	if len(flow.Flow.Patterns) == 0 {
		err = executions.UpdateStep(request.Config, request.Execution.ID.String(), models.ExecutionSteps{
			ID: request.Step.ID,
			Messages: []models.Message{
				{
					Title: "Pattern Check",
					Lines: []string{"No patterns are defined", "Continue to next step"},
				},
			},
			Status:     "success",
			FinishedAt: time.Now(),
		}, request.Platform)
		if err != nil {
			return plugins.Response{
				Success: false,
			}, err
		}

		return plugins.Response{
			Success: true,
		}, nil
	}

	// convert payload to string
	payloadBytes, err := json.Marshal(request.Alert.Payload)
	if err != nil {
		return plugins.Response{
			Success: false,
		}, err
	}
	payloadString := string(payloadBytes)

	patternMissMatched := 0

	for _, pattern := range flow.Flow.Patterns {
		value := gjson.Get(payloadString, pattern.Key)

		if pattern.Type == "equals" {
			if value.String() == pattern.Value {
				err := executions.UpdateStep(request.Config, request.Execution.ID.String(), models.ExecutionSteps{
					ID: request.Step.ID,
					Messages: []models.Message{
						{
							Title: "Pattern Check",
							Lines: []string{`Pattern: ` + pattern.Key + ` == ` + pattern.Value + ` matched`, "Continue to next step"},
						},
					},
				}, request.Platform)
				if err != nil {
					return plugins.Response{
						Success: false,
					}, err
				}
			} else {
				err = executions.UpdateStep(request.Config, request.Execution.ID.String(), models.ExecutionSteps{
					ID: request.Step.ID,
					Messages: []models.Message{
						{
							Title: "Pattern Check",
							Lines: []string{`Pattern: ` + pattern.Key + ` == ` + pattern.Value + ` not found`},
						},
					},
					Status:     "canceled",
					FinishedAt: time.Now(),
				}, request.Platform)
				if err != nil {
					return plugins.Response{
						Success: false,
					}, err
				}
				patternMissMatched++
			}
		} else if pattern.Type == "not_equals" {
			if value.String() != pattern.Value {
				err := executions.UpdateStep(request.Config, request.Execution.ID.String(), models.ExecutionSteps{
					ID: request.Step.ID,
					Messages: []models.Message{
						{
							Title: "Pattern Check",
							Lines: []string{`Pattern: ` + pattern.Key + ` != ` + pattern.Value + ` not found`, "Continue to next step"},
						},
					},
				}, request.Platform)
				if err != nil {
					return plugins.Response{
						Success: false,
					}, err
				}
			} else {
				err = executions.UpdateStep(request.Config, request.Execution.ID.String(), models.ExecutionSteps{
					ID: request.Step.ID,
					Messages: []models.Message{
						{
							Title: "Pattern Check",
							Lines: []string{`Pattern: ` + pattern.Key + ` != ` + pattern.Value + ` matched`},
						},
					},
					Status:     "canceled",
					FinishedAt: time.Now(),
				}, request.Platform)
				if err != nil {
					return plugins.Response{
						Success: false,
					}, err
				}
				patternMissMatched++
			}
		} else if pattern.Type == "contains" {
			if !strings.Contains(value.String(), pattern.Value) {
				err := executions.UpdateStep(request.Config, request.Execution.ID.String(), models.ExecutionSteps{
					ID: request.Step.ID,
					Messages: []models.Message{
						{
							Title: "Pattern Check",
							Lines: []string{`Pattern: ` + pattern.Key + ` contains ` + pattern.Value + ` not found`, "Continue to next step"},
						},
					},
				}, request.Platform)
				if err != nil {
					return plugins.Response{}, err
				}
			} else {
				err = executions.UpdateStep(request.Config, request.Execution.ID.String(), models.ExecutionSteps{
					ID: request.Step.ID,
					Messages: []models.Message{
						{
							Title: "Pattern Check",
							Lines: []string{`Pattern: ` + pattern.Key + ` contains ` + pattern.Value + ` matched`},
						},
					},
					Status:     "canceled",
					FinishedAt: time.Now(),
				}, request.Platform)
				if err != nil {
					return plugins.Response{
						Success: false,
					}, err
				}
				patternMissMatched++
			}
		} else if pattern.Type == "not_contains" {
			if strings.Contains(value.String(), pattern.Value) {
				err := executions.UpdateStep(request.Config, request.Execution.ID.String(), models.ExecutionSteps{
					ID: request.Step.ID,
					Messages: []models.Message{
						{
							Title: "Pattern Check",
							Lines: []string{`Pattern: ` + pattern.Key + ` not contains ` + pattern.Value + ` not found`, "Continue to next step"},
						},
					},
				}, request.Platform)
				if err != nil {
					return plugins.Response{
						Success: false,
					}, err
				}
			} else {
				err = executions.UpdateStep(request.Config, request.Execution.ID.String(), models.ExecutionSteps{
					ID: request.Step.ID,
					Messages: []models.Message{
						{
							Title: "Pattern Check",
							Lines: []string{`Pattern: ` + pattern.Key + ` not contains ` + pattern.Value + ` matched`},
						},
					},
					Status:     "canceled",
					FinishedAt: time.Now(),
				}, request.Platform)
				if err != nil {
					return plugins.Response{
						Success: false,
					}, err
				}
				patternMissMatched++
			}
		}
	}

	if patternMissMatched > 0 {
		err = executions.UpdateStep(request.Config, request.Execution.ID.String(), models.ExecutionSteps{
			ID: request.Step.ID,
			Messages: []models.Message{
				{
					Title: "Pattern Check",
					Lines: []string{"Some patterns did not match", "Cancel execution"},
				},
			},
			Status:     "noPatternMatch",
			FinishedAt: time.Now(),
		}, request.Platform)
		if err != nil {
			return plugins.Response{
				Success: false,
			}, err
		}
		return plugins.Response{
			Data: map[string]interface{}{
				"status": "noPatternMatch",
			},
			Success: false,
		}, nil
	} else {
		err = executions.UpdateStep(request.Config, request.Execution.ID.String(), models.ExecutionSteps{
			ID: request.Step.ID,
			Messages: []models.Message{
				{
					Title: "Pattern Check",
					Lines: []string{"All patterns matched", "Continue to next step"},
				},
			},
			Status:     "success",
			FinishedAt: time.Now(),
		}, request.Platform)
		if err != nil {
			return plugins.Response{
				Success: false,
			}, err
		}
		return plugins.Response{
			Success: true,
		}, nil
	}
}

func (p *Plugin) EndpointRequest(request plugins.EndpointRequest) (plugins.Response, error) {
	return plugins.Response{
		Success: false,
	}, errors.New("not implemented")
}

func (p *Plugin) Info() (models.Plugin, error) {
	var plugin = models.Plugin{
		Name:    "Pattern Check",
		Type:    "action",
		Version: "1.2.0",
		Author:  "JustNZ",
		Action: models.Action{
			Name:        "Pattern Check",
			Description: "Check flow patterns",
			Plugin:      "pattern_check",
			Icon:        "solar:list-check-minimalistic-bold",
			Category:    "Utility",
			Params:      nil,
		},
		Endpoint: models.Endpoint{},
	}

	return plugin, nil
}

// PluginRPCServer is the RPC server for Plugin
type PluginRPCServer struct {
	Impl plugins.Plugin
}

func (s *PluginRPCServer) ExecuteTask(request plugins.ExecuteTaskRequest, resp *plugins.Response) error {
	result, err := s.Impl.ExecuteTask(request)
	*resp = result
	return err
}

func (s *PluginRPCServer) EndpointRequest(request plugins.EndpointRequest, resp *plugins.Response) error {
	result, err := s.Impl.EndpointRequest(request)
	*resp = result
	return err
}

func (s *PluginRPCServer) Info(args interface{}, resp *models.Plugin) error {
	result, err := s.Impl.Info()
	*resp = result
	return err
}

// PluginServer is the implementation of plugin.Plugin interface
type PluginServer struct {
	Impl plugins.Plugin
}

func (p *PluginServer) Server(*plugin.MuxBroker) (interface{}, error) {
	return &PluginRPCServer{Impl: p.Impl}, nil
}

func (p *PluginServer) Client(b *plugin.MuxBroker, c *rpc.Client) (interface{}, error) {
	return &plugins.PluginRPC{Client: c}, nil
}

func main() {
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: plugin.HandshakeConfig{
			ProtocolVersion:  1,
			MagicCookieKey:   "PLUGIN_MAGIC_COOKIE",
			MagicCookieValue: "hello",
		},
		Plugins: map[string]plugin.Plugin{
			"plugin": &PluginServer{Impl: &Plugin{}},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}
