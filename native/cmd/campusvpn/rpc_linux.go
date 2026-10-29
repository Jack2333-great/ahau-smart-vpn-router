package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"
)

// RPC bridge accepts only explicitly declared operations. Credentials travel
// through stdin and the private Unix socket, never process arguments.
func rpcControl(ctx context.Context, socket, action, method string) error {
	enc := json.NewEncoder(os.Stdout)
	if action == "list" {
		return enc.Encode(map[string]any{"status": map[string]string{}, "login": map[string]string{"username": "", "password": ""}, "disconnect": map[string]string{}, "reconnect": map[string]string{}})
	}
	if action != "call" {
		return errors.New("unsupported RPC action")
	}
	req := controlRequest{}
	switch method {
	case "status", "disconnect", "reconnect":
		req.Action = method
	case "login":
		var input struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if json.NewDecoder(io.LimitReader(os.Stdin, 8193)).Decode(&input) != nil {
			return enc.Encode(map[string]any{"ok": false, "message": "invalid request"})
		}
		req.Action = "save-login"
		req.Username = input.Username
		req.Password = input.Password
		input.Username = ""
		input.Password = ""
	default:
		return errors.New("unsupported RPC method")
	}
	callCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	result, e := requestControl(callCtx, socket, req)
	req = controlRequest{}
	if e != nil {
		return enc.Encode(map[string]any{"ok": false, "state": "unavailable", "message": "service unavailable"})
	}
	return enc.Encode(result)
}
