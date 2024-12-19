package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	name         = "Boltcoin"
	symbol       = "BOLC"
	supply       = 50000000000000000
	initialReward = 1.0
)

// Transaction structure
type Transaction struct {
	From      string
	To        string
	Amount    float64
	Signature string
}

// Block definition
type Block struct {
	Index        int
	Timestamp    time.Time
	Transactions []Transaction
	Hash         string
	PreviousHash string
	Nonce        int
}

// Blockchain definition
type Blockchain struct {
	Chain        []Block
	PendingTxns  []Transaction
	Difficulty   int
	BalanceSheet map[string]float64
	TotalSupply  float64
	mu           sync.Mutex
}

// CORS Middleware
func enableCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Utility: Generate a wallet
func generateWallet() (privateKey *ecdsa.PrivateKey, publicKey string) {
	privateKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	publicKey = fmt.Sprintf("%x", elliptic.Marshal(elliptic.P256(), privateKey.X, privateKey.Y))
	return
}

// Utility: Verify a transaction signature
func verifyTransaction(tx *Transaction, publicKeyHex string) bool {
	// Decode sender's public key from its hex representation
	pubKeyBytes := []byte(publicKeyHex)
	x, y := elliptic.Unmarshal(elliptic.P256(), pubKeyBytes)
	if x == nil || y == nil {
		return false
	}
	publicKey := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}

	// Hash the transaction data (excluding the signature)
	txData := tx.From + tx.To + fmt.Sprintf("%f", tx.Amount)
	txHash := sha256.Sum256([]byte(txData))

	// Decode the signature from its hex representation
	signatureParts := strings.Split(tx.Signature, ":")
	if len(signatureParts) != 2 {
		return false
	}
	r := new(big.Int)
	s := new(big.Int)
	r.SetString(signatureParts[0], 16)
	s.SetString(signatureParts[1], 16)

	// Verify the signature
	return ecdsa.Verify(publicKey, txHash[:], r, s)
}

// Utility: Calculate hash of a block
func (b *Block) calculateHash() string {
	data, _ := json.Marshal(b.Transactions)
	blockData := strconv.Itoa(b.Index) + b.PreviousHash + string(data) + b.Timestamp.String() + strconv.Itoa(b.Nonce)
	hash := sha256.Sum256([]byte(blockData))
	return fmt.Sprintf("%x", hash)
}

// Utility: Mine a block
func (b *Block) mineBlock(difficulty int) {
	target := strings.Repeat("0", difficulty)
	for !strings.HasPrefix(b.Hash, target) {
		b.Nonce++
		b.Hash = b.calculateHash()
	}
}

// Create new Blockchain
func createBlockchain(difficulty int) *Blockchain {
	genesisBlock := Block{
		Index:        0,
		Timestamp:    time.Now(),
		Transactions: []Transaction{},
		Hash:         "0",
	}
	return &Blockchain{
		Chain:        []Block{genesisBlock},
		PendingTxns:  []Transaction{},
		Difficulty:   difficulty,
		BalanceSheet: make(map[string]float64),
	}
}

// Add a transaction
func (bc *Blockchain) addTransaction(tx Transaction) bool {
	bc.mu.Lock()
	defer bc.mu.Unlock()

	// Verify the transaction signature
	if !verifyTransaction(&tx, tx.From) {
		log.Println("Invalid transaction signature")
		return false
	}

	// Check sender's balance
	if tx.Amount <= 0 || bc.BalanceSheet[tx.From] < tx.Amount {
		log.Println("Insufficient balance or invalid amount")
		return false
	}

	// Add transaction to pending pool
	bc.PendingTxns = append(bc.PendingTxns, tx)
	bc.BalanceSheet[tx.From] -= tx.Amount
	bc.BalanceSheet[tx.To] += tx.Amount
	return true
}

// Add a block
func (bc *Blockchain) addBlock(minerAddress string) {
	bc.mu.Lock()
	defer bc.mu.Unlock()

	reward := initialReward // Use a local variable for calculations

	// Check if mining rewards can still be issued
	if bc.TotalSupply+reward > supply {
		reward = supply - bc.TotalSupply
		if reward <= 0 {
			reward = 0
		}
	}

	// Create reward transaction
	if reward > 0 {
		rewardTx := Transaction{
			From:      "SYSTEM",
			To:        minerAddress,
			Amount:    reward,
			Signature: "",
		}
		bc.PendingTxns = append(bc.PendingTxns, rewardTx)
		bc.BalanceSheet[minerAddress] += reward
		bc.TotalSupply += reward
	}

	// Create a new block
	lastBlock := bc.Chain[len(bc.Chain)-1]
	newBlock := Block{
		Index:        len(bc.Chain),
		Timestamp:    time.Now(),
		Transactions: bc.PendingTxns,
		PreviousHash: lastBlock.Hash,
	}
	newBlock.mineBlock(bc.Difficulty)

	// Append the block and clear pending transactions
	bc.Chain = append(bc.Chain, newBlock)
	bc.PendingTxns = []Transaction{}
}

// REST API for Node Interaction
func main() {
	bc := createBlockchain(2)

	mux := http.NewServeMux()

	mux.HandleFunc("/wallet/new", func(w http.ResponseWriter, r *http.Request) {
		privateKey, publicKey := generateWallet()
		response := map[string]string{
			"privateKey": fmt.Sprintf("%x", privateKey.D),
			"publicKey":  publicKey,
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	})

	mux.HandleFunc("/balance", func(w http.ResponseWriter, r *http.Request) {
		wallet := r.URL.Query().Get("wallet")
		if balance, exists := bc.BalanceSheet[wallet]; exists {
			json.NewEncoder(w).Encode(map[string]float64{wallet: balance})
		} else {
			http.Error(w, "Wallet not found", http.StatusNotFound)
		}
	})

	mux.HandleFunc("/transactions", func(w http.ResponseWriter, r *http.Request) {
		wallet := r.URL.Query().Get("wallet")
		var userTxns []Transaction
		for _, block := range bc.Chain {
			for _, txn := range block.Transactions {
				if txn.From == wallet || txn.To == wallet {
					userTxns = append(userTxns, txn)
				}
			}
		}
		json.NewEncoder(w).Encode(userTxns)
	})

	mux.HandleFunc("/transactions/new", func(w http.ResponseWriter, r *http.Request) {
		var tx Transaction
		json.NewDecoder(r.Body).Decode(&tx)
		if bc.addTransaction(tx) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Transaction added successfully!"))
		} else {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Invalid transaction!"))
		}
	})

	mux.HandleFunc("/mine", func(w http.ResponseWriter, r *http.Request) {
		minerAddress := r.URL.Query().Get("address")
		if minerAddress == "" {
			http.Error(w, "Miner address is required", http.StatusBadRequest)
			return
		}
		bc.addBlock(minerAddress)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(bc.Chain[len(bc.Chain)-1])
	})

	mux.HandleFunc("/chain", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(bc.Chain)
	})

	// Wrap all routes with CORS middleware
	http.ListenAndServe(":8080", enableCORS(mux))
}