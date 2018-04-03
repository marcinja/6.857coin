package main

import (
	"bytes"
	//	"crypto/aes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const TEAM_NAME = "marcinja"
const NODE_URL = "http://6857coin.csail.mit.edu"
const TIME_RANGE = 119

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

type ExplorerBlock struct {
	ID            string    `json:"id"`
	Header        Header    `json:"header"`
	Block         string    `json:"block"`
	Blockheight   int       `json:"blockheight"`
	Ismainchain   bool      `json:"ismainchain"`
	Evermainchain bool      `json:"evermainchain"`
	Totaldiff     int       `json:"totaldiff"`
	Timestamp     time.Time `json:"timestamp"`
}

func nextBlock() (bool, Header) {
	resp, err := http.Get(NODE_URL + "/next")
	if (err != nil) || !(resp.StatusCode >= 200 && resp.StatusCode <= 299) {
		fmt.Println("Failed to get block", err)
		return false, Header{}
	}
	defer resp.Body.Close()

	header := Header{}
	json.NewDecoder(resp.Body).Decode(&header)
	return true, header

	/*
			b, _ := json.Marshal(&header)
			buf := bytes.NewBuffer(b)
			header2 := Header{}
			json.NewDecoder(buf).Decode(&header2)
		fmt.Println(header, b, header2)
	*/
}

func addBlock(block Block) bool {
	b, _ := json.Marshal(&block)
	buf := bytes.NewBuffer(b)

	resp, err := http.Post(NODE_URL, "/add", buf)
	if (err != nil) || !(resp.StatusCode >= 200 && resp.StatusCode <= 299) {
		fmt.Println("Add block failed", err, resp.StatusCode)
		return false
	}

	fmt.Println(resp.Body, block)

	return true
}

func test1() {
	t := "/block/d127746e056fa60278353a19ba090b04c021855e56e136c915778eff1f5afdfa"
	resp, err := http.Get(NODE_URL + t)
	if (err != nil) || !(resp.StatusCode >= 200 && resp.StatusCode <= 299) {
		fmt.Println("Failed to get block", err)
	}
	defer resp.Body.Close()

	block := ExplorerBlock{}
	json.NewDecoder(resp.Body).Decode(&block)

	fmt.Println(block.ID)

	s := hashBlockHeader(&block.Header)
	fmt.Println(s)
}

// return SHA256 hash of header.
func hashBlockHeader(header *Header) string {
	// TODO: determine corrext size to allocate
	b := make([]byte, 0)
	h := sha256.New()
	//	b, _ := json.Marshal(&header)

	id, _ := hex.DecodeString(header.ParentID)
	b = append(b, id[:]...)

	root, _ := hex.DecodeString(header.Root)
	b = append(b, root[:]...)

	diffBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(diffBuf, header.Difficulty)
	b = append(b, diffBuf[:]...)

	tsBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(tsBuf, header.Timestamp)
	b = append(b, tsBuf[:]...)

	for i := 0; i < 3; i++ {
		nonceBuf := make([]byte, 8)
		binary.BigEndian.PutUint64(nonceBuf, header.Nonces[i])
		b = append(b, nonceBuf[:]...)
	}

	b = append(b, byte(header.Version))

	h.Write(b)
	sum := h.Sum(nil)
	hexStr := hex.EncodeToString(sum)
	fmt.Println("Sum: ", hexStr)

	return hexStr
}

func makeNextBlock(header Header) Block {

	newHeader := Header{
		ParentID:   "", //TODO: SHA256 header,
		Root:       "",
		Difficulty: 86,
		Timestamp:  0,
		Version:    0,
	}
	block := Block{
		newHeader,
		TEAM_NAME,
	}

	return block
}

func currentTime() uint64 {
	return uint64(time.Now().Unix())
}

func main() {
	//nextBlock()
	//	addBlock(Block{})
	test1()
}
