package main

import (
	"encoding/json"
	"fmt"
	"net/http"
)

const TEAM_NAME = "marcinja-hujh"
const NODE_URL = "http://6857coin.csail.mit.edu"

type Header struct {
	ParentID   string    `json:"parentid`
	Root       string    `json:"root"`
	Difficulty uint64    `json:"difficulty"`
	Timestamp  uint64    `json:"timestamp"`
	Nonces     [3]uint64 `json:"nonces"`
	Version    uint8     `json:"version"`
}

type Block struct {
	Header Header `json:"header"`
	Block  string `json:"block"`
}

func nextBlock() {
	resp, err := http.Get(NODE_URL + "/next")
	if err != nil {
		fmt.Println("Failed to get block", err)
		return
	}
	defer resp.Body.Close()

	header := Header{}
	json.NewDecoder(resp.Body).Decode(&header)

	fmt.Println(header)
}

func main() {
	nextBlock()
}
