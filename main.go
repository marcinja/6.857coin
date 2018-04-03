package main

import (
	"bytes"
	"crypto/aes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/bits"
	"math/rand"
	"net/http"
	"sync"
	"time"
)

const TEAM_NAME = "marcinja, hujh"
const NODE_URL = "http://6857coin.csail.mit.edu"
const TIME_RANGE = 119
const AES_BLOCK_SIZE = 16
const MaxUint64 = 1<<64 - 1

const DEBUG = false

type Header struct {
	ParentID   string    `json:"parentid"`
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

func nextBlockTemplate() (Header, bool) {
	resp, err := http.Get(NODE_URL + "/next")
	if (err != nil) || !(resp.StatusCode >= 200 && resp.StatusCode <= 299) {
		fmt.Println("Failed to get block", err)
		return Header{}, false
	}
	defer resp.Body.Close()

	header := Header{}
	json.NewDecoder(resp.Body).Decode(&header)
	return header, true
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

// return SHA256 hash of header.
func hashBlockHeader(header *Header) []byte {
	b := make([]byte, 0)
	h := sha256.New()

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

	return sum
}

// getSeeds return seed and seed2 when given a header.
func getSeeds(header *Header) ([]byte, []byte) {
	b := make([]byte, 0)
	h1 := sha256.New()

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

	nonceBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(nonceBuf, header.Nonces[0])
	b = append(b, nonceBuf[:]...)

	b = append(b, byte(header.Version))

	h1.Write(b)
	seed := h1.Sum(nil)

	// Now hash the first seed to get seed2.
	h2 := sha256.New()
	h2.Write(seed)
	seed2 := h2.Sum(nil)

	return seed, seed2
}

type uint128 struct {
	low  uint64
	high uint64
}

func Add(x, y uint128) uint128 {
	z := uint128{}
	z.high = x.high + y.high
	z.low = x.low + y.low

	// If low bits sum overflows, add carry bit to high.
	if z.low < x.low {
		z.high++
	}

	return z
}

func HammingDistance(x, y uint128) int {
	return bits.OnesCount64(x.low^y.low) + bits.OnesCount64(x.high^y.high)
}

// TODO: check errors like a reasonable human being
func computePoW(i, j uint64, seed, seed2 []byte) int {
	seedCipher, _ := aes.NewCipher(seed)
	seed2Cipher, _ := aes.NewCipher(seed2)

	// Plaintexts:
	A_i_p := make([]byte, 16)
	binary.BigEndian.PutUint64(A_i_p[8:], i)
	A_j_p := make([]byte, 16)
	binary.BigEndian.PutUint64(A_j_p[8:], j)
	B_i_p := make([]byte, 16)
	binary.BigEndian.PutUint64(B_i_p[8:], i)
	B_j_p := make([]byte, 16)
	binary.BigEndian.PutUint64(B_j_p[8:], j)

	//fmt.Println("\n plain: \n", A_i_p, A_j_p, B_i_p, B_j_p)
	//fmt.Println(seed, seed2)

	// Ciphertexts:
	A_i := make([]byte, 16)
	seedCipher.Encrypt(A_i, A_i_p)
	A_j := make([]byte, 16)
	seedCipher.Encrypt(A_j, A_j_p)
	B_i := make([]byte, 16)
	seed2Cipher.Encrypt(B_i, B_i_p)
	B_j := make([]byte, 16)
	seed2Cipher.Encrypt(B_j, B_j_p)

	//fmt.Println("CIPHERS: \n", A_i, A_j, B_i, B_j)

	A_i_int128 := uint128{
		low:  binary.BigEndian.Uint64(A_i[0:8]),
		high: binary.BigEndian.Uint64(A_i[8:16]),
	}

	A_j_int128 := uint128{
		low:  binary.BigEndian.Uint64(A_j[0:8]),
		high: binary.BigEndian.Uint64(A_j[8:16]),
	}
	B_i_int128 := uint128{
		low:  binary.BigEndian.Uint64(B_i[0:8]),
		high: binary.BigEndian.Uint64(B_i[8:16]),
	}

	B_j_int128 := uint128{
		low:  binary.BigEndian.Uint64(B_j[0:8]),
		high: binary.BigEndian.Uint64(B_j[8:16]),
	}

	return HammingDistance(Add(A_i_int128, B_j_int128), Add(A_j_int128, B_i_int128))
}

func hammingDistance(x, y []byte) int {
	// go doesn't let you get an array pointer from a slice.
	// so we just hardcode these numbers and assume x,y are 32 bytes,
	// this way we avoid copying.
	x_int := binary.BigEndian.Uint64(x[0:8])
	x_int2 := binary.BigEndian.Uint64(x[8:16])

	y_int := binary.BigEndian.Uint64(y[0:8])
	y_int2 := binary.BigEndian.Uint64(y[8:16])
	return bits.OnesCount64(x_int^y_int) + bits.OnesCount64(x_int2^y_int2)
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

func test1() {
	// Genesis block
	//t := "/block/d127746e056fa60278353a19ba090b04c021855e56e136c915778eff1f5afdfa"

	//	t := "/block/1daf4834bb21c214cf6df62046533963d8d1058b6b327b248541b621af4ce582"

	t := "/block/d127746e056fa60278353a19ba090b04c021855e56e136c915778eff1f5afdfa"
	resp, err := http.Get(NODE_URL + t)
	if (err != nil) || !(resp.StatusCode >= 200 && resp.StatusCode <= 299) {
		fmt.Println("Failed to get block", err)
	}
	defer resp.Body.Close()

	block := ExplorerBlock{}
	json.NewDecoder(resp.Body).Decode(&block)

	s := hashBlockHeader(&block.Header)
	fmt.Println(s)

	seed, seed2 := getSeeds(&block.Header)
	/*
		for i := 1; i < MaxUint64/4; i++ {
			for j := 1; j < MaxUint64/4; j++ {
				work := computePoW(uint64(i), uint64(j), seed, seed2)
				fmt.Println(i, j, work)
				if 128-94 >= work {
					fmt.Println(i, j, work)
					break
				}
			}
		}
	*/
	work := computePoW(199952, 12, seed, seed2)

	fmt.Println("seeds and work", seed, seed2, 128-86, work)
	fmt.Println(block)
}

// Maximum number of elements stored for A and B.
const MAX_TABLE_SIZE = 1000

// Number of goroutines that will be mining.
const N_WORKERS = 4

type Miner struct {
	mu           sync.Mutex
	currentBlock Block // currentBlock is the block being mined.
	A_table      [MAX_TABLE_SIZE]uint128
	B_table      [MAX_TABLE_SIZE]uint128
}

func (*Miner) SetNewBlockTemplate() {
	headerTemplate, ok := nextBlockTemplate()
	if !ok {
		fmt.Println("ERR TODO: REMOVE THIS")
		return
	}

	// Create block for miner
	block := Block{
		Header: headerTemplate,
		Block:  TEAM_NAME,
	}
	randNonce := rand.Uint64()
	block.Header.Nonces[0] = randNonce
}

func MakeMiner() *Miner {
	m := Miner{}
	m.SetNewBlockTemplate()

	go m.Mine()

	return &m
}

func (*Miner) Mine() {

}
