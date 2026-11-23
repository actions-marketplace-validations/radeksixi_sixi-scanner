package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestMCPServeStdioHandshakeAndTools(t *testing.T) {
	input := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"sixi_list_techniques","arguments":{"min_severity":"critical"}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"sixi_scan","arguments":{"target":"echo","only":["probe.llm01.instruction-override"],"attempts":1}}}`,
	}, "\n") + "\n"

	var out bytes.Buffer
	if err := serveMCPStdio(context.Background(), strings.NewReader(input), &out); err != nil {
		t.Fatalf("serveMCPStdio: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 4 {
		t.Fatalf("expected 4 JSON-RPC responses (notification must be silent), got %d:\n%s", len(lines), out.String())
	}

	// 1. initialize
	var initResp struct {
		Result struct {
			ProtocolVersion string `json:"protocolVersion"`
			ServerInfo      struct {
				Name string `json:"name"`
			} `json:"serverInfo"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &initResp); err != nil {
		t.Fatal(err)
	}
	if initResp.Result.ServerInfo.Name != "sixi-scanner" {
		t.Errorf("serverInfo.name = %q, want sixi-scanner", initResp.Result.ServerInfo.Name)
	}

	// 2. tools/list
	var listResp struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(lines[1]), &listResp); err != nil {
		t.Fatal(err)
	}
	if len(listResp.Result.Tools) != 3 {
		t.Fatalf("expected 3 MCP tools, got %d: %+v", len(listResp.Result.Tools), listResp.Result.Tools)
	}

	// 3. sixi_list_techniques
	var techResp struct {
		Result struct {
			IsError bool `json:"isError"`
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(lines[2]), &techResp); err != nil {
		t.Fatal(err)
	}
	if techResp.Result.IsError || len(techResp.Result.Content) == 0 || !strings.Contains(techResp.Result.Content[0].Text, `"techniques"`) {
		t.Fatalf("unexpected sixi_list_techniques output: %+v", techResp)
	}

	// 4. sixi_scan on echo
	var scanResp struct {
		Result struct {
			IsError bool `json:"isError"`
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(lines[3]), &scanResp); err != nil {
		t.Fatal(err)
	}
	if scanResp.Result.IsError || len(scanResp.Result.Content) == 0 || !strings.Contains(scanResp.Result.Content[0].Text, `"findings"`) {
		t.Fatalf("unexpected sixi_scan output: %+v", scanResp)
	}
}
