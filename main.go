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
	"os"
	"runtime/pprof"
	"sync"
	"time"
)

const TEAM_NAME = "marcinja, hujh"
const NODE_URL = "http://6857coin.csail.mit.edu"
const TIME_RANGE = 119
const AES_BLOCK_SIZE = 16
const MaxUint64 = 1<<64 - 1

const DEBUG = false
const GET_RATE = true

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

	fmt.Println(string(b))
	resp, err := http.Post(NODE_URL+"/add", "", buf)
	defer resp.Body.Close()
	if (err != nil) || !(resp.StatusCode >= 200 && resp.StatusCode <= 299) {
		fmt.Println("Add block failed", err, resp)
	}
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

func SeededAES(m_buffer, c_buffer, seed []byte, i uint64) uint128 {
	cipher, _ := aes.NewCipher(seed)

	binary.BigEndian.PutUint64(m_buffer[8:], i)
	cipher.Encrypt(c_buffer, m_buffer)

	A_i_int128 := uint128{
		low:  binary.BigEndian.Uint64(c_buffer[0:8]),
		high: binary.BigEndian.Uint64(c_buffer[8:16]),
	}

	return A_i_int128
}

// too many allocs :(
func SeededAES_Old(seed []byte, i uint64) uint128 {
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

	killChans    []chan struct{}
	pairsChecked []int
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

	contents := []byte(TEAM_NAME)
	h := sha256.New()
	h.Write(contents)
	root := h.Sum(nil)

	block.Header.Root = hex.EncodeToString(root)

	m.currentBlock = block
}

func (m *Miner) SetupMiner() {
	m.SetNewBlockTemplate()
	m.newBlockChan = make(chan Block, 1)
	m.start = time.Now()

	m.killChans = make([]chan struct{}, N_WORKERS)
	m.pairsChecked = make([]int, N_WORKERS)

	for i := 0; i < N_WORKERS; i++ {
		m.killChans[i] = make(chan struct{}, 1)
	}
}

func StartMiner(m Miner) {
	m.SetupMiner()
	go m.PollServer()
	m.SendTasks()
	m.MasterLoop()
}

func (m *Miner) SendTasks() {
	fmt.Printf("MINING BLOCK: %+v\n\n ", m.currentBlock)
	// Iterate over partitions of nonce_space and assign workers.
	for i := 0; i < N_WORKERS; i++ {
		fmt.Println("NONCE RANGE: ", i, uint64(i)*N_NONCES, uint64((i+1))*N_NONCES)
		go m.MineRange(i, uint64(i)*N_NONCES, uint64((i+1))*N_NONCES, m.killChans[i])
	}

}

func (m *Miner) MasterLoop() {
	// Timeout needed to update timestamp.
	timestamp_timeout := 119 * time.Second
	timeout := time.NewTimer(timestamp_timeout)

	start := time.Now()

	for {
		select {
		case <-m.newBlockChan:
			if GET_RATE {
				continue
			}

			fmt.Println("\n~~~ NEW BLOCK FOUND ~~~")
			m.mu.Lock()
			for i := 0; i < N_WORKERS; i++ {
				m.killChans[i] <- struct{}{}
			}
			m.SetupMiner()
			m.SendTasks()
			m.mu.Unlock()
			timeout.Reset(timestamp_timeout)

		case <-timeout.C:
			fmt.Println("\n~~~TIMEOUT EXCEEDED~~~")
			m.mu.Lock()
			for i := 0; i < N_WORKERS; i++ {
				fmt.Println(i)
				m.killChans[i] <- struct{}{}
			}

			if GET_RATE {
				total := 0
				for i := 0; i < N_WORKERS; i++ {
					total += m.pairsChecked[i]
				}
				fmt.Println("\n\n TOTAL CHECKED after TIME: ", total, time.Since(start))
				panic("DONE")
			}

			m.SetupMiner()
			m.SendTasks()
			m.mu.Unlock()
			timeout.Reset(timestamp_timeout)
		}
	}
}

const POLLING_TIMEOUT = 1 * time.Second

// Poll server for new block templates (i.e. check if another block has been mined.)
// Runs in one goroutine only.
func (m *Miner) PollServer() {
	for {
		//fmt.Println("TABLES SIZES: ", m.A_size, m.B_size)
		h, ok := nextBlockTemplate()
		fmt.Println("Parent ID, matching num, A_size: ", h.ParentID, 128-h.Difficulty, m.A_size)

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
	f, _ := os.Create("cpu.out")
	pprof.StartCPUProfile(f)
	defer pprof.StopCPUProfile()
	StartMiner(Miner{})
}

func (m *Miner) MineRange(workerIdx int, start, end uint64, kill chan struct{}) {
	seed, seed2 := getSeeds(&m.currentBlock.Header)

	cipher, _ := aes.NewCipher(seed)
	cipher2, _ := aes.NewCipher(seed2)

	done := false

	num_checked := 0
	id := rand.Uint64()

	m_buffer := make([]byte, 16)
	c_buffer := make([]byte, 16)

	for i := start; i < end; i++ {
		for j := start + 1; j < end; j++ {
			select {
			case <-kill:
				fmt.Println("HEREEEEEEEEEEEEEEE", num_checked)
				m.pairsChecked[workerIdx] = num_checked
				return
			default:
			}

			binary.BigEndian.PutUint64(m_buffer[8:], uint64(i))
			cipher.Encrypt(c_buffer, m_buffer)
			A_i := uint128{
				low:  binary.BigEndian.Uint64(c_buffer[0:8]),
				high: binary.BigEndian.Uint64(c_buffer[8:16]),
			}
			cipher2.Encrypt(c_buffer, m_buffer)
			B_i := uint128{
				low:  binary.BigEndian.Uint64(c_buffer[0:8]),
				high: binary.BigEndian.Uint64(c_buffer[8:16]),
			}

			binary.BigEndian.PutUint64(m_buffer[8:], uint64(j))
			cipher.Encrypt(c_buffer, m_buffer)
			A_j := uint128{
				low:  binary.BigEndian.Uint64(c_buffer[0:8]),
				high: binary.BigEndian.Uint64(c_buffer[8:16]),
			}
			cipher2.Encrypt(c_buffer, m_buffer)
			B_j := uint128{
				low:  binary.BigEndian.Uint64(c_buffer[0:8]),
				high: binary.BigEndian.Uint64(c_buffer[8:16]),
			}

			/*
				A_i := SeededAES(m_buffer, c_buffer, seed, uint64(i))
				B_i := SeededAES(m_buffer, c_buffer, seed2, uint64(i))

				A_j := SeededAES(m_buffer, c_buffer, seed, uint64(j))
				B_j := SeededAES(m_buffer, c_buffer, seed2, uint64(j))
			*/

			dist := HammingDistance(Add(A_i, B_j), Add(A_j, B_i))

			num_checked++
			if dist < 33 {
				fmt.Println("DIST: ", dist, time.Since(m.start))
				fmt.Println("nonces checked", i, j, num_checked, time.Since(m.start), id)
			}

			if dist < 128-int(m.currentBlock.Header.Difficulty) {
				fmt.Println("dif:, ", 128-int(m.currentBlock.Header.Difficulty))
				fmt.Println("DIST: ", dist, time.Since(m.start))
				m.mu.Lock()
				m.currentBlock.Header.Nonces[1] = uint64(i)
				m.currentBlock.Header.Nonces[2] = uint64(j)

				addBlock(m.currentBlock)
				fmt.Println(m.currentBlock)
				m.mu.Unlock()
				done = true
			}

			if (j % 1000) == 0 {
				m.pairsChecked[workerIdx] = num_checked
			}

			if done {
				m.pairsChecked[workerIdx] = num_checked
				<-kill
				return
			}
		}
	}
	m.pairsChecked[workerIdx] = num_checked
	<-kill
}

func (m *Miner) MineRangeOld(workerIdx int, start, end uint64, kill chan struct{}) {
	seed, seed2 := getSeeds(&m.currentBlock.Header)

	done := false

	num_checked := 0
	id := rand.Uint64()

	m_buffer := make([]byte, 16)
	c_buffer := make([]byte, 16)

	for i := start; i < end; i++ {
		select {
		case <-kill:
			fmt.Println("HEREEEEEEEEEEEEEEE", num_checked)
			m.pairsChecked[workerIdx] = num_checked
			return
		default:
		}

		//fmt.Println("mining nonce: ", i)
		// Compute A(i), B(i) (since this is our nonce-range).
		// If tables aren't filled up, we will add them to the tables after.
		A_i := SeededAES(m_buffer, c_buffer, seed, uint64(i))
		B_i := SeededAES(m_buffer, c_buffer, seed2, uint64(i))

		checkAgainstA_Tables := func(j, v interface{}) bool {
			A_j := v.(uint128)

			B_j_e, ok := m.B_memo.Load(j)
			if !ok {
				return true
			}
			B_j := B_j_e.(uint128)

			dist := HammingDistance(Add(A_i, B_j), Add(A_j, B_i))

			num_checked++
			if dist < 33 {
				fmt.Println("DIST: ", dist, time.Since(m.start))
				fmt.Println("nonces checked", num_checked, time.Since(m.start), id)
			}

			if dist < 128-int(m.currentBlock.Header.Difficulty) {
				fmt.Println("dif:, ", 128-int(m.currentBlock.Header.Difficulty))
				fmt.Println("DIST: ", dist, time.Since(m.start))
				m.mu.Lock()
				m.currentBlock.Header.Nonces[1] = uint64(i)
				m.currentBlock.Header.Nonces[2] = j.(uint64)
				addBlock(m.currentBlock)
				fmt.Println(m.currentBlock)
				m.mu.Unlock()
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

		m.pairsChecked[workerIdx] = num_checked

		if done {
			m.pairsChecked[workerIdx] = num_checked
			<-kill
			return
		}
	}
	m.pairsChecked[workerIdx] = num_checked
	<-kill
}
