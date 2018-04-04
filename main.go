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

	//fmt.Println(resp.Body, block)

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

func SeededAES(seed []byte, i uint64) uint128 {
	cipher, _ := aes.NewCipher(seed)

	A_i_p := make([]byte, 16)
	binary.BigEndian.PutUint64(A_i_p[8:], i)

	A_i := make([]byte, 16)
	cipher.Encrypt(A_i, A_i_p)

	A_i_int128 := uint128{
		low:  binary.BigEndian.Uint64(A_i[0:8]),
		high: binary.BigEndian.Uint64(A_i[8:16]),
	}

	return A_i_int128
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
func currentTime() uint64 {
	return uint64(time.Now().UnixNano())
}

// Maximum number of elements stored for A and B.
const MAX_TABLE_SIZE = 25000

// Number of goroutines that will be mining.
const N_WORKERS = 4
const N_NONCES = MaxUint64 / N_WORKERS

type Miner struct {
	mu           sync.Mutex
	currentBlock Block // currentBlock is the block being mined.
	newBlockChan chan Block

	A_memo sync.Map
	B_memo sync.Map

	A_size int
	B_size int

	start time.Time
}

func (m *Miner) SetNewBlockTemplate() {
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

	// Create block for miner
	randNonce := rand.Uint64()
	block.Header.Nonces[0] = randNonce
	block.Header.Timestamp = currentTime()

	m.currentBlock = block
}

func MakeMiner() {
	m := Miner{}
	m.SetNewBlockTemplate()
	m.newBlockChan = make(chan Block, 1)
	m.start = time.Now()

	go m.PollServer()
	m.Mine(m.currentBlock)
}

func (m *Miner) Mine(block Block) {
	fmt.Printf("MINING BLOCK: %+v\n\n ", block)
	killChans := make([]chan struct{}, N_WORKERS)
	successChan := make(chan struct{}, N_WORKERS) // TODO: make it so we continue mining on our chain greedily.

	for i := 0; i < N_WORKERS; i++ {
		killChans[i] = make(chan struct{}, 1)
	}

	// Iterate over partitions of nonce_space and assign workers.
	for i := 0; i < N_WORKERS; i++ {
		fmt.Println("NONCE RANGE: ", i, uint64(i)*N_NONCES, uint64((i+1))*N_NONCES)
		go m.MineRange(uint64(i)*N_NONCES, uint64((i+1))*N_NONCES, killChans[i], successChan)
	}

	for {
		select {
		case newBlock := <-m.newBlockChan:
			m.mu.Lock()
			defer m.mu.Unlock()
			for i := 0; i < N_WORKERS; i++ {
				killChans[i] <- struct{}{}
			}

			go m.Mine(newBlock)
			return

		case <-successChan:
			// wait for poll server to let you know? TODO
			time.Sleep(POLLING_TIMEOUT)
		}
	}
}

const POLLING_TIMEOUT = 500 * time.Millisecond

// Poll server for new block templates (i.e. check if another block has been mined.)
// Runs in one goroutine only.
func (m *Miner) PollServer() {
	for {
		//fmt.Println("TABLES SIZES: ", m.A_size, m.B_size)
		h, ok := nextBlockTemplate()

		q := 25
		p := 1
		i := rand.Intn(q)
		if i < p {
			fmt.Println("Parent ID, matching num, A_size: ", h.ParentID, 128-h.Difficulty, m.A_size)
		}

		if !ok {
			// TODO decide on what behavior is reasonable here
			continue
		}

		// Detect when next block has changed.
		if h.ParentID != m.currentBlock.Header.ParentID {
			// Create block for miner
			block := Block{
				Header: h,
				Block:  TEAM_NAME,
			}
			randNonce := rand.Uint64()
			block.Header.Nonces[0] = randNonce
			block.Header.Timestamp = currentTime()
			m.newBlockChan <- block
		}
		time.Sleep(POLLING_TIMEOUT)
	}
}

func main() {
	MakeMiner()
}

func (m *Miner) MineRange(start, end uint64, kill, success chan struct{}) {
	seed, seed2 := getSeeds(&m.currentBlock.Header)

	done := false

	num_checked := 0
	id := rand.Uint64()

	for i := start; i < end; i++ {
		//fmt.Println("mining nonce: ", i)
		// Compute A(i), B(i) (since this is our nonce-range).
		// If tables aren't filled up, we will add them to the tables after.
		A_i := SeededAES(seed, uint64(i))
		B_i := SeededAES(seed2, uint64(i))

		checkAgainstA_Tables := func(j, v interface{}) bool {
			A_j := v.(uint128)

			B_j_e, ok := m.B_memo.Load(j)
			if !ok {
				return true
			}
			B_j := B_j_e.(uint128)

			dist := HammingDistance(Add(A_i, B_j), Add(A_j, B_i))

			num_checked++
			if dist < 35 {
				fmt.Println("DIST: ", dist, time.Since(m.start))
				fmt.Println("nonces checked", num_checked, time.Since(m.start), id)
			}

			if dist <= 128-int(m.currentBlock.Header.Difficulty) {
				m.mu.Lock()
				m.currentBlock.Header.Nonces[1] = uint64(i)
				m.currentBlock.Header.Nonces[2] = j.(uint64)
				ok := addBlock(m.currentBlock)
				fmt.Println(m.currentBlock)
				m.mu.Unlock()

				if ok {
					success <- struct{}{}
				}

				done = true
			}

			return true
		}

		m.A_memo.Range(checkAgainstA_Tables)

		// Insert into memo table now.
		if (m.A_size <= MAX_TABLE_SIZE) && (m.B_size <= MAX_TABLE_SIZE) {
			m.A_memo.Store(i, A_i)
			m.B_memo.Store(i, B_i)
			m.mu.Lock()
			m.A_size++
			m.B_size++
			m.mu.Unlock()
		}

		if done {
			return
		}
	}
}
