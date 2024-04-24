package server

import (
	"encoding/json"
	"fmt"
	"net/http"
)

func ReturnJSON(w http.ResponseWriter, resp interface{}, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	encoder := json.NewEncoder(w)
	err := encoder.Encode(resp)
	if err != nil {
		panic(fmt.Errorf("error encoding response: %w", err))
	}
}

func ReturnErrorJSON(w http.ResponseWriter, msg string, statusCode int) {
	resp := map[string]interface{}{
		"error": msg,
	}
	ReturnJSON(w, resp, statusCode)
}
