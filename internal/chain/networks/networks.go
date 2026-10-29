// Package networks assembles the default testnet chain registry.
package networks

import (
	"math/big"

	"thresholdvault/internal/chain"
	"thresholdvault/internal/chain/evm"
	"thresholdvault/internal/chain/tron"
	"thresholdvault/internal/chain/utxo"
)

// Chain IDs.
const (
	EthereumSepolia = "ethereum-sepolia"
	BSCTestnet      = "bsc-testnet"
	BitcoinTestnet  = "bitcoin-testnet"
	LitecoinTestnet = "litecoin-testnet"
	DashTestnet     = "dash-testnet"
	TronNile        = "tron-nile"
)

// RPC endpoints, overridable from configuration.
type RPC struct {
	Sepolia    string
	BSCTestnet string
	TronNile   string
}

// Default builds the testnet registry. Tokens are added in the token
// configuration step and must be verified before use.
func Default(rpc RPC) *chain.Registry {
	return chain.NewRegistry(
		evm.New(evm.Config{
			ID: EthereumSepolia, Name: "Ethereum Sepolia", ChainID: big.NewInt(11155111),
			Native:   chain.Asset{Symbol: "ETH", Decimals: 18, Standard: "native"},
			TokenStd: "erc20", RPCURL: rpc.Sepolia,
			ExplorerTx: "https://sepolia.etherscan.io/tx/%s",
		}),
		evm.New(evm.Config{
			ID: BSCTestnet, Name: "BNB Smart Chain Testnet", ChainID: big.NewInt(97),
			Native:   chain.Asset{Symbol: "BNB", Decimals: 18, Standard: "native"},
			TokenStd: "bep20", RPCURL: rpc.BSCTestnet,
			ExplorerTx: "https://testnet.bscscan.com/tx/%s",
		}),
		utxo.New(utxo.BitcoinTestnet),
		utxo.New(utxo.LitecoinTestnet),
		utxo.New(utxo.DashTestnet),
		tron.New(tron.Config{ID: TronNile, Name: "TRON Nile Testnet", APIURL: rpc.TronNile}),
	)
}
