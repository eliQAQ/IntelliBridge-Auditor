package ethereum

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"sync"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	ecommon "github.com/ethereum/go-ethereum/common"
	etypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/semaphore"

	"gitlab.com/thorchain/thornode/v3/bifrost/blockscanner"
	btypes "gitlab.com/thorchain/thornode/v3/bifrost/blockscanner/types"
	"gitlab.com/thorchain/thornode/v3/bifrost/metrics"
	"gitlab.com/thorchain/thornode/v3/bifrost/pkg/chainclients/shared/evm"
	"gitlab.com/thorchain/thornode/v3/bifrost/pkg/chainclients/shared/evm/types"
	"gitlab.com/thorchain/thornode/v3/bifrost/pkg/chainclients/shared/signercache"
	"gitlab.com/thorchain/thornode/v3/bifrost/pubkeymanager"
	"gitlab.com/thorchain/thornode/v3/bifrost/thorclient"
	stypes "gitlab.com/thorchain/thornode/v3/bifrost/thorclient/types"
	"gitlab.com/thorchain/thornode/v3/common"
	"gitlab.com/thorchain/thornode/v3/common/cosmos"
	tokenlist "gitlab.com/thorchain/thornode/v3/common/tokenlist"
	"gitlab.com/thorchain/thornode/v3/config"
	"gitlab.com/thorchain/thornode/v3/constants"
	memo "gitlab.com/thorchain/thornode/v3/x/thorchain/memo"
)

// SolvencyReporter is to report solvency info to THORNode
type SolvencyReporter func(int64) error

const (
	ethToken        = "0x0000000000000000000000000000000000000000"
	symbolMethod    = "symbol"
	decimalMethod   = "decimals"
	defaultDecimals = 18 // on ETH , consolidate all decimals to 18, in Wei
	tenGwei         = 10000000000
	// prefixTokenMeta declares prefix to use in leveldb to avoid conflicts
	prefixTokenMeta    = `eth-tokenmeta-` // nolint gosec:G101 not a hardcoded credential
	prefixBlockMeta    = `eth-blockmeta-`
	prefixSignedTxItem = `signed-txitem-`
)

// ETHScanner is a scanner that understand how to interact with ETH chain ,and scan block , parse smart contract etc
type ETHScanner struct {
	cfg                   config.BifrostBlockScannerConfiguration
	logger                zerolog.Logger
	db                    blockscanner.ScannerStorage
	m                     *metrics.Metrics
	errCounter            *prometheus.CounterVec
	gasPriceChanged       bool
	gasPrice              *big.Int
	lastReportedGasPrice  uint64
	client                *ethclient.Client
	blockMetaAccessor     evm.BlockMetaAccessor
	globalErrataQueue     chan<- stypes.ErrataBlock
	globalNetworkFeeQueue chan<- common.NetworkFee
	vaultABI              *abi.ABI
	erc20ABI              *abi.ABI
	tokens                *evm.LevelDBTokenMeta
	bridge                thorclient.ThorchainBridge
	pubkeyMgr             pubkeymanager.PubKeyValidator
	eipSigner             etypes.Signer
	currentBlockHeight    int64
	gasCache              []*big.Int
	solvencyReporter      SolvencyReporter
	whitelistTokens       []tokenlist.ERC20Token
	signerCacheManager    *signercache.CacheManager
}

// NewETHScanner create a new instance of ETHScanner
func NewETHScanner(cfg config.BifrostBlockScannerConfiguration,
	storage blockscanner.ScannerStorage,
	chainID *big.Int,
	client *ethclient.Client,
	bridge thorclient.ThorchainBridge,
	m *metrics.Metrics,
	pubkeyMgr pubkeymanager.PubKeyValidator,
	solvencyReporter SolvencyReporter,
	signerCacheManager *signercache.CacheManager,
) (*ETHScanner, error) {
	if storage == nil {
		return nil, errors.New("storage is nil")
	}
	if m == nil {
		return nil, errors.New("metrics manager is nil")
	}
	if client == nil {
		return nil, errors.New("ETH client is nil")
	}
	if pubkeyMgr == nil {
		return nil, errors.New("pubkey manager is nil")
	}
	blockMetaAccessor, err := evm.NewLevelDBBlockMetaAccessor(prefixBlockMeta, prefixSignedTxItem, storage.GetInternalDb())
	if err != nil {
		return nil, fmt.Errorf("fail to create block meta accessor: %w", err)
	}
	tokens, err := evm.NewLevelDBTokenMeta(storage.GetInternalDb(), prefixTokenMeta)
	if err != nil {
		return nil, fmt.Errorf("fail to create token meta db: %w", err)
	}
	err = tokens.SaveTokenMeta("ETH", ethToken, defaultDecimals)
	if err != nil {
		return nil, err
	}
	vaultABI, erc20ABI, err := evm.GetContractABI(routerContractABI, erc20ContractABI)
	if err != nil {
		return nil, fmt.Errorf("fail to create contract abi: %w", err)
	}

	return &ETHScanner{
		cfg:                  cfg,
		logger:               log.Logger.With().Str("module", "block_scanner").Str("chain", common.ETHChain.String()).Logger(),
		errCounter:           m.GetCounterVec(metrics.BlockScanError(common.ETHChain)),
		client:               client,
		db:                   storage,
		m:                    m,
		gasPrice:             big.NewInt(initialGasPrice),
		lastReportedGasPrice: 0,
		gasPriceChanged:      false,
		blockMetaAccessor:    blockMetaAccessor,
		tokens:               tokens,
		bridge:               bridge,
		vaultABI:             vaultABI,
		erc20ABI:             erc20ABI,
		eipSigner:            etypes.NewPragueSigner(chainID),
		pubkeyMgr:            pubkeyMgr,
		gasCache:             make([]*big.Int, 0),
		solvencyReporter:     solvencyReporter,
		whitelistTokens:      tokenlist.GetETHTokenList().Tokens,
		signerCacheManager:   signerCacheManager,
	}, nil
}

// GetGasPrice returns current gas price
func (e *ETHScanner) GetGasPrice() *big.Int {
	if e.cfg.FixedGasRate > 0 {
		return big.NewInt(e.cfg.FixedGasRate)
	}
	return e.gasPrice
}

func (e *ETHScanner) getContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), e.cfg.HTTPRequestTimeout)
}

// GetHeight return latest block height
func (e *ETHScanner) GetHeight() (int64, error) {
	ctx, cancel := e.getContext()
	defer cancel()
	height, err := e.client.BlockNumber(ctx)
	if err != nil {
		return -1, fmt.Errorf("fail to get block height: %w", err)
	}
	return int64(height), nil
}

// GetNetworkFee returns current chain network fee according to Bifrost.
func (e *ETHScanner) GetNetworkFee() (transactionSize, transactionFeeRate uint64) {
	return e.cfg.MaxGasLimit, e.lastReportedGasPrice
}

// FetchMemPool get tx from mempool
func (e *ETHScanner) FetchMemPool(_ int64) (stypes.TxIn, error) {
	return stypes.TxIn{}, nil
}

// GetTokens return all the token meta data
func (e *ETHScanner) GetTokens() ([]*types.TokenMeta, error) {
	return e.tokens.GetTokens()
}

// FetchTxs query the ETH chain to get txs in the given block height
func (e *ETHScanner) FetchTxs(height, chainHeight int64) (stypes.TxIn, error) {
	block, err := e.getRPCBlock(height)
	if err != nil {
		return stypes.TxIn{}, err
	}
	txIn, err := e.processBlock(block)
	if err != nil {
		e.logger.Error().Err(err).Int64("height", height).Msg("fail to search tx in block")
		return stypes.TxIn{}, fmt.Errorf("fail to process block: %d, err:%w", height, err)
	}
	// blockMeta need to be saved , even there is no transactions found on this block at the time of scan
	// because at the time of scan , so the block hash will be stored, and it can be used to detect re-org
	blockMeta := types.NewBlockMeta(block.Header(), txIn)
	if err = e.blockMetaAccessor.SaveBlockMeta(blockMeta.Height, blockMeta); err != nil {
		e.logger.Err(err).Msgf("fail to save block meta of height: %d ", blockMeta.Height)
	}

	e.currentBlockHeight = height
	pruneHeight := height - e.cfg.MaxReorgRescanBlocks
	if pruneHeight > 0 {
		defer func() {
			if err := e.blockMetaAccessor.PruneBlockMeta(pruneHeight); err != nil {
				e.logger.Err(err).Msgf("fail to prune block meta, height(%d)", pruneHeight)
			}
		}()
	}

	// skip reporting network fee and solvency if block more than flexibility blocks from tip
	if chainHeight-height > e.cfg.ObservationFlexibilityBlocks {
		return txIn, nil
	}

	// gas price to 1e8 from 1e18
	gasPrice := e.GetGasPrice()
	tcGasPrice := new(big.Int).Div(gasPrice, big.NewInt(1e10)).Uint64()
	if tcGasPrice == 0 {
		tcGasPrice = 1
	}

	// post to thorchain if there is a fee and it has changed
	if gasPrice.Cmp(big.NewInt(0)) != 0 && tcGasPrice != e.lastReportedGasPrice {
		e.globalNetworkFeeQueue <- common.NetworkFee{
			Chain:           common.ETHChain,
			Height:          height,
			TransactionSize: e.cfg.MaxGasLimit,
			TransactionRate: tcGasPrice,
		}

		e.lastReportedGasPrice = tcGasPrice
	}

	if e.solvencyReporter != nil {
		if err = e.solvencyReporter(height); err != nil {
			e.logger.Err(err).Msg("fail to report Solvency info to THORNode")
		}
	}
	return txIn, nil
}

// updateGasPrice records base fee + 25th percentile priority fee, rounded up 10 gwei.
func (e *ETHScanner) updateGasPrice(baseFee *big.Int, priorityFees []*big.Int) {
	// skip empty blocks
	if len(priorityFees) == 0 {
		return
	}

	// find the 25th percentile priority fee in the block
	sort.Slice(priorityFees, func(i, j int) bool { return priorityFees[i].Cmp(priorityFees[j]) == -1 })
	priorityFee := priorityFees[len(priorityFees)/4]

	// consider gas price as base fee + 25th percentile priority fee
	gasPriceWei := new(big.Int).Add(baseFee, priorityFee)

	// round the price up to nearest configured resolution
	resolution := big.NewInt(e.cfg.GasPriceResolution)
	gasPriceWei.Add(gasPriceWei, new(big.Int).Sub(resolution, big.NewInt(1)))
	gasPriceWei = gasPriceWei.Div(gasPriceWei, resolution)
	gasPriceWei = gasPriceWei.Mul(gasPriceWei, resolution)

	// add to the cache
	e.gasCache = append(e.gasCache, gasPriceWei)
	if len(e.gasCache) > e.cfg.GasCacheBlocks {
		e.gasCache = e.gasCache[(len(e.gasCache) - e.cfg.GasCacheBlocks):]
	}

	e.updateGasPriceFromCache()
}

func (e *ETHScanner) updateGasPriceFromCache() {
	// skip update unless cache is full
	if len(e.gasCache) < e.cfg.GasCacheBlocks {
		return
	}

	// compute the mean of cache
	sum := new(big.Int)
	for _, fee := range e.gasCache {
		sum.Add(sum, fee)
	}
	mean := new(big.Int).Quo(sum, big.NewInt(int64(e.cfg.GasCacheBlocks)))

	// compute the standard deviation of cache
	std := new(big.Int)
	for _, fee := range e.gasCache {
		v := new(big.Int).Sub(fee, mean)
		v.Mul(v, v)
		std.Add(std, v)
	}
	std.Quo(std, big.NewInt(int64(e.cfg.GasCacheBlocks)))
	std.Sqrt(std)

	// mean + 3x standard deviation over cache blocks
	e.gasPrice = mean.Add(mean, std.Mul(std, big.NewInt(3)))

	// record metrics
	gasPriceFloat, _ := new(big.Float).SetInt64(e.gasPrice.Int64()).Float64()
	e.m.GetGauge(metrics.GasPrice(common.ETHChain)).Set(gasPriceFloat)
	e.m.GetCounter(metrics.GasPriceChange(common.ETHChain)).Inc()
}

// processBlock extracts transactions from block
func (e *ETHScanner) processBlock(block *etypes.Block) (stypes.TxIn, error) {
	height := int64(block.NumberU64())
	txIn := stypes.TxIn{
		Chain:    common.ETHChain,
		TxArray:  nil,
		Filtered: false,
		MemPool:  false,
	}

	// update gas price
	var priorityFees []*big.Int
	for _, tx := range block.Transactions() {
		tipCap := tx.GasTipCap()
		if tipCap == nil {
			tipCap = big.NewInt(0)
		}
		priorityFees = append(priorityFees, tipCap)
	}
	e.updateGasPrice(block.BaseFee(), priorityFees)

	reorgedTxIns, err := e.processReorg(block.Header())
	if err != nil {
		e.logger.Error().Err(err).Msgf("fail to process reorg for block %d", height)
		return txIn, err
	}
	if len(reorgedTxIns) > 0 {
		for _, item := range reorgedTxIns {
			if len(item.TxArray) == 0 {
				continue
			}
			txIn.TxArray = append(txIn.TxArray, item.TxArray...)
		}
	}

	if block.Transactions().Len() == 0 {
		return txIn, nil
	}

	txInBlock, err := e.extractTxs(block)
	if err != nil {
		return txIn, err
	}
	if len(txInBlock.TxArray) > 0 {
		txIn.TxArray = append(txIn.TxArray, txInBlock.TxArray...)
	}
	return txIn, nil
}

func (e *ETHScanner) extractTxs(block *etypes.Block) (stypes.TxIn, error) {
	txInbound := stypes.TxIn{
		Chain:    common.ETHChain,
		Filtered: false,
		MemPool:  false,
	}

	sem := semaphore.NewWeighted(e.cfg.Concurrency)
	mu := sync.Mutex{}
	wg := sync.WaitGroup{}

	processTx := func(tx *etypes.Transaction) {
		defer wg.Done()
		if err := sem.Acquire(context.Background(), 1); err != nil {
			e.logger.Err(err).Msg("fail to acquire semaphore")
			return
		}
		defer sem.Release(1)

		if tx.To() == nil {
			return
		}

		// just try to remove the transaction hash from key value store
		// it doesn't matter whether the transaction is ours or not , success or failure
		// as long as the transaction id matches
		if err := e.blockMetaAccessor.RemoveSignedTxItem(tx.Hash().String()); err != nil {
			e.logger.Err(err).Msgf("fail to remove signed tx item, hash:%s", tx.Hash().String())
		}

		txInItem, err := e.fromTxToTxIn(tx)
		if err != nil {
			e.logger.Error().Err(err).Str("hash", tx.Hash().Hex()).Msg("fail to get one tx from server")
			return
		}
		if txInItem == nil {
			return
		}
		// sometimes if a transaction failed due to gas problem , it will have no `to` address
		if len(txInItem.To) == 0 {
			return
		}
		if len([]byte(txInItem.Memo)) > constants.MaxMemoSize {
			return
		}
		txInItem.BlockHeight = block.Number().Int64()
		mu.Lock()
		txInbound.TxArray = append(txInbound.TxArray, txInItem)
		mu.Unlock()
		e.logger.Debug().Str("hash", tx.Hash().Hex()).Msgf("%s got %d tx", e.cfg.ChainID, 1)
	}

	// process txs in parallel
	for _, tx := range block.Transactions() {
		// skip blob transactions
		if tx.Type() == etypes.BlobTxType {
			continue
		}

		wg.Add(1)
		go processTx(tx)
	}
	wg.Wait()

	count := len(txInbound.TxArray)
	if count == 0 {
		e.logger.Info().Int64("block", int64(block.NumberU64())).Msg("no tx need to be processed in this block")
		return stypes.TxIn{}, nil
	}
	e.logger.Debug().Int64("block", int64(block.NumberU64())).Msgf("there are %d tx in this block need to process", count)
	return txInbound, nil
}

func (e *ETHScanner) onObservedTxIn(txIn stypes.TxInItem, blockHeight int64) {
	blockMeta, err := e.blockMetaAccessor.GetBlockMeta(blockHeight)
	if err != nil {
		e.logger.Err(err).Msgf("fail to get block meta on block height(%d)", blockHeight)
		return
	}

	if blockMeta == nil {
		e.logger.Error().Msgf("block meta for height:%d is nil", blockHeight)
		return
	}
	for _, item := range blockMeta.Transactions {
		if item.Hash == txIn.Tx {
			return
		}
	}

	blockMeta.Transactions = append(blockMeta.Transactions, types.TransactionMeta{
		Hash:        txIn.Tx,
		BlockHeight: blockHeight,
	})
	if err = e.blockMetaAccessor.SaveBlockMeta(blockHeight, blockMeta); err != nil {
		e.logger.Err(err).Msgf("fail to save block meta to storage,block height(%d)", blockHeight)
	}
}

// processReorg will compare block's parent hash and the block hash we have in store
// when there is a reorg detected , it will return true, other false
func (e *ETHScanner) processReorg(block *etypes.Header) ([]stypes.TxIn, error) {
	previousHeight := block.Number.Int64() - 1
	prevBlockMeta, err := e.blockMetaAccessor.GetBlockMeta(previousHeight)
	if err != nil {
		return nil, fmt.Errorf("fail to get block meta of height(%d) : %w", previousHeight, err)
	}
	if prevBlockMeta == nil {
		return nil, nil
	}
	// the block's previous hash need to be the same as the block hash chain client recorded in block meta
	// blockMetas[PreviousHeight].BlockHash == Block.PreviousHash
	if strings.EqualFold(prevBlockMeta.BlockHash, block.ParentHash.Hex()) {
		return nil, nil
	}
	e.logger.Info().Msgf("re-org detected, current block height:%d ,previous block hash is : %s , however block meta at height: %d, block hash is %s", block.Number.Int64(), block.ParentHash.Hex(), prevBlockMeta.Height, prevBlockMeta.BlockHash)
	heights, err := e.reprocessTxs()
	if err != nil {
		e.logger.Err(err).Msg("fail to reprocess all txs")
	}
	var txIns []stypes.TxIn
	for _, item := range heights {
		e.logger.Info().Msgf("rescan block height: %d", item)
		var block *etypes.Block
		block, err = e.getRPCBlock(item)
		if err != nil {
			e.logger.Err(err).Msgf("fail to get block from RPC endpoint, height:%d", item)
			continue
		}
		if block.Transactions().Len() == 0 {
			continue
		}
		var txIn stypes.TxIn
		txIn, err = e.extractTxs(block)
		if err != nil {
			e.logger.Err(err).Msgf("fail to extract txs from block (%d)", item)
			continue
		}
		if len(txIn.TxArray) > 0 {
			txIns = append(txIns, txIn)
		}
	}
	return txIns, nil
}

// reprocessTx will be kicked off only when chain client detected a re-org on ethereum chain
// it will read through all the block meta data from local storage, and go through all the txs.
// For each transaction, it will send a RPC request to ethereuem chain, double check whether the TX exist or not
// if the tx still exist, then it is all good, if a transaction previous we detected, however doesn't exist anymore, that means
// the transaction had been removed from chain, chain client should report to thorchain
// []int64 is the block heights that need to be rescanned
func (e *ETHScanner) reprocessTxs() ([]int64, error) {
	blockMetas, err := e.blockMetaAccessor.GetBlockMetas()
	if err != nil {
		return nil, fmt.Errorf("fail to get block metas from local storage: %w", err)
	}
	var rescanBlockHeights []int64
	for _, blockMeta := range blockMetas {
		metaTxs := make([]types.TransactionMeta, 0)
		var errataTxs []stypes.ErrataTx
		for _, tx := range blockMeta.Transactions {
			if e.checkTransaction(tx.Hash) {
				e.logger.Debug().Msgf("block height: %d, tx: %s still exist", blockMeta.Height, tx.Hash)
				metaTxs = append(metaTxs, tx)
				continue
			}
			// this means the tx doesn't exist in chain ,thus should errata it
			errataTxs = append(errataTxs, stypes.ErrataTx{
				TxID:  common.TxID(tx.Hash),
				Chain: common.ETHChain,
			})
		}
		if len(errataTxs) > 0 {
			e.globalErrataQueue <- stypes.ErrataBlock{
				Height: blockMeta.Height,
				Txs:    errataTxs,
			}
		}
		// Let's get the block again to fix the block hash
		var block *etypes.Header
		block, err = e.getHeader(blockMeta.Height)
		if err != nil {
			e.logger.Err(err).Msgf("fail to get block verbose tx result: %d", blockMeta.Height)
			rescanBlockHeights = append(rescanBlockHeights, blockMeta.Height)
			continue
		}
		if !strings.EqualFold(blockMeta.BlockHash, block.Hash().Hex()) {
			// if the block hash is different as previously recorded , then the block should be rescanned
			rescanBlockHeights = append(rescanBlockHeights, blockMeta.Height)
		}
		blockMeta.PreviousHash = block.ParentHash.Hex()
		blockMeta.BlockHash = block.Hash().Hex()
		blockMeta.Transactions = metaTxs
		if err = e.blockMetaAccessor.SaveBlockMeta(blockMeta.Height, blockMeta); err != nil {
			e.logger.Err(err).Msgf("fail to save block meta of height: %d ", blockMeta.Height)
		}
	}
	return rescanBlockHeights, nil
}

func (e *ETHScanner) checkTransaction(hash string) bool {
	ctx, cancel := e.getContext()
	defer cancel()
	tx, pending, err := e.client.TransactionByHash(ctx, ecommon.HexToHash(hash))
	if err != nil || tx == nil {
		return false
	}

	// pending transactions may fail, but we should only errata when there is certainty
	if pending {
		e.logger.Warn().Msgf("tx: %s is in pending status", hash)
		return true // unknown, prefer false positive
	}

	// ensure the tx was successful
	receipt, err := e.getReceipt(hash)
	if err != nil {
		e.logger.Warn().Err(err).Msgf("fail to get receipt for tx: %s", hash)
		return true // unknown, prefer false positive
	}
	return receipt.Status == etypes.ReceiptStatusSuccessful
}

func (e *ETHScanner) getReceipt(hash string) (*etypes.Receipt, error) {
	ctx, cancel := e.getContext()
	defer cancel()
	return e.client.TransactionReceipt(ctx, ecommon.HexToHash(hash))
}

func (e *ETHScanner) getHeader(height int64) (*etypes.Header, error) {
	ctx, cancel := e.getContext()
	defer cancel()
	return e.client.HeaderByNumber(ctx, big.NewInt(height))
}

func (e *ETHScanner) getBlock(height int64) (*etypes.Block, error) {
	ctx, cancel := e.getContext()
	defer cancel()
	return e.client.BlockByNumber(ctx, big.NewInt(height))
}

func (e *ETHScanner) getRPCBlock(height int64) (*etypes.Block, error) {
	block, err := e.getBlock(height)
	if err == ethereum.NotFound {
		return nil, btypes.ErrUnavailableBlock
	}
	if err != nil {
		return nil, fmt.Errorf("fail to fetch block: %w", err)
	}
	return block, nil
}

func (e *ETHScanner) getDecimals(token string) (uint64, error) {
	if IsETH(token) {
		return defaultDecimals, nil
	}
	to := ecommon.HexToAddress(token)
	input, err := e.erc20ABI.Pack(decimalMethod)
	if err != nil {
		return defaultDecimals, fmt.Errorf("fail to pack decimal method: %w", err)
	}
	ctx, cancel := e.getContext()
	defer cancel()
	res, err := e.client.CallContract(ctx, ethereum.CallMsg{
		To:   &to,
		Data: input,
	}, nil)
	if err != nil {
		return defaultDecimals, fmt.Errorf("fail to call smart contract get decimals: %w", err)
	}
	output, err := e.erc20ABI.Unpack(decimalMethod, res)
	if err != nil {
		return defaultDecimals, fmt.Errorf("fail to unpack decimal method call result: %w", err)
	}
	switch output[0].(type) {
	case uint8:
		decimals, ok := abi.ConvertType(output[0], new(uint8)).(*uint8)
		if !ok {
			return defaultDecimals, fmt.Errorf("dev error: fail to cast uint8")
		}
		return uint64(*decimals), nil
	case *big.Int:
		decimals, ok := abi.ConvertType(output[0], new(*big.Int)).(*big.Int)
		if !ok {
			return defaultDecimals, fmt.Errorf("dev error: fail to cast big.Int")
		}
		return decimals.Uint64(), nil
	}
	return defaultDecimals, fmt.Errorf("%s is %T fail to parse it", output[0], output[0])
}

// . and - had been reserved to use in THORChain symbol
// and + similarly is not accepted by common package NewSymbol's isAlphaNumeric
var symbolReplacer = strings.NewReplacer(".", "", "-", "", `\u0000`, "", "\u0000", "", "+", "")

func sanitiseSymbol(symbol string) string {
	return symbolReplacer.Replace(symbol)
}

func (e *ETHScanner) getSymbol(token string) (string, error) {
	if IsETH(token) {
		return "ETH", nil
	}
	to := ecommon.HexToAddress(token)
	input, err := e.erc20ABI.Pack(symbolMethod)
	if err != nil {
		return "", nil
	}
	ctx, cancel := e.getContext()
	defer cancel()
	res, err := e.client.CallContract(ctx, ethereum.CallMsg{
		To:   &to,
		Data: input,
	}, nil)
	if err != nil {
		return "", fmt.Errorf("fail to call to smart contract and get symbol: %w", err)
	}
	var symbol string
	output, err := e.erc20ABI.Unpack(symbolMethod, res)
	if err != nil {
		symbol = string(res)
		e.logger.Err(err).Msgf("fail to unpack symbol method call,token address: %s , symbol: %s", token, symbol)
		return sanitiseSymbol(symbol), nil
	}
	// nolint
	symbol = *abi.ConvertType(output[0], new(string)).(*string)
	return sanitiseSymbol(symbol), nil
}

// isToValidContractAddress this method make sure the transaction to address is to THORChain router or a whitelist address
func (e *ETHScanner) isToValidContractAddress(addr *ecommon.Address, includeWhiteList bool) bool {
	// get the smart contract used by thornode
	contractAddresses := e.pubkeyMgr.GetContracts(common.ETHChain)
	if includeWhiteList || useWhitelistSmartContract {
		contractAddresses = append(contractAddresses, whitelistSmartContractAddress...)
	}
	// combine the whitelist smart contract address
	for _, item := range contractAddresses {
		if strings.EqualFold(item.String(), addr.String()) {
			return true
		}
	}
	return false
}

func (e *ETHScanner) getTokenMeta(token string) (types.TokenMeta, error) {
	tokenMeta, err := e.tokens.GetTokenMeta(token)
	if err != nil {
		return types.TokenMeta{}, fmt.Errorf("fail to get token meta: %w", err)
	}
	if tokenMeta.IsEmpty() {
		isWhiteListToken := false
		for _, item := range e.whitelistTokens {
			if strings.EqualFold(item.Address, token) {
				isWhiteListToken = true
				break
			}
		}

		if !isWhiteListToken {
			return types.TokenMeta{}, fmt.Errorf("token: %s is not whitelisted", token)
		}
		var symbol string
		symbol, err = e.getSymbol(token)
		if err != nil {
			return types.TokenMeta{}, fmt.Errorf("fail to get symbol: %w", err)
		}
		var decimals uint64
		decimals, err = e.getDecimals(token)
		if err != nil {
			e.logger.Err(err).Msgf("fail to get decimals from smart contract, default to: %d", defaultDecimals)
		}
		e.logger.Info().Msgf("token:%s, decimals: %d", token, decimals)
		tokenMeta = types.NewTokenMeta(symbol, token, decimals)
		if err = e.tokens.SaveTokenMeta(symbol, token, decimals); err != nil {
			return types.TokenMeta{}, fmt.Errorf("fail to save token meta: %w", err)
		}
	}
	return tokenMeta, nil
}

// convertAmount will convert the amount to 1e8 , the decimals used by THORChain
func (e *ETHScanner) convertAmount(token string, amt *big.Int) cosmos.Uint {
	if IsETH(token) {
		return cosmos.NewUintFromBigInt(amt).QuoUint64(common.One * 100)
	}
	decimals := uint64(defaultDecimals)
	tokenMeta, err := e.getTokenMeta(token)
	if err != nil {
		e.logger.Err(err).Msgf("fail to get token meta for token address: %s", token)
	}
	if !tokenMeta.IsEmpty() {
		decimals = tokenMeta.Decimal
	}
	if decimals != defaultDecimals {
		var value big.Int
		amt = amt.Mul(amt, value.Exp(big.NewInt(10), big.NewInt(defaultDecimals), nil))
		amt = amt.Div(amt, value.Exp(big.NewInt(10), big.NewInt(int64(decimals)), nil))
	}
	return cosmos.NewUintFromBigInt(amt).QuoUint64(common.One * 100)
}

// return value 0 means use the default value which is common.THORChainDecimals, use 1e8 as precision
func (e *ETHScanner) getTokenDecimalsForTHORChain(token string) int64 {
	if IsETH(token) {
		return 0
	}
	tokenMeta, err := e.getTokenMeta(token)
	if err != nil {
		e.logger.Err(err).Msgf("fail to get token meta for token address: %s", token)
	}
	if tokenMeta.IsEmpty() {
		return 0
	}
	// when the token's precision is more than THORChain , that's fine , just use THORChainDecimals
	if tokenMeta.Decimal >= common.THORChainDecimals {
		return 0
	}
	return int64(tokenMeta.Decimal)
}

func (e *ETHScanner) getAssetFromTokenAddress(token string) (common.Asset, error) {
	if IsETH(token) {
		return common.ETHAsset, nil
	}
	tokenMeta, err := e.getTokenMeta(token)
	if err != nil {
		return common.EmptyAsset, fmt.Errorf("fail to get token meta: %w", err)
	}
	if tokenMeta.IsEmpty() {
		return common.EmptyAsset, fmt.Errorf("token metadata is empty")
	}
	return common.NewAsset(fmt.Sprintf("ETH.%s-%s", tokenMeta.Symbol, strings.ToUpper(tokenMeta.Address)))
}

// getTxInFromSmartContract returns txInItem
func (e *ETHScanner) getTxInFromSmartContract(tx *etypes.Transaction, receipt *etypes.Receipt, maxLogs int64) (*stypes.TxInItem, error) {
	e.logger.Debug().Msg("parse tx from smart contract")
	txInItem := &stypes.TxInItem{
		Tx: tx.Hash().Hex()[2:],
	}
	sender, err := e.eipSigner.Sender(tx)
	if err != nil {
		return nil, fmt.Errorf("fail to get sender: %w", err)
	}
	txInItem.Sender = strings.ToLower(sender.String())
	// 1 is Transaction success state
	if receipt.Status != 1 {
		e.logger.Info().Msgf("tx(%s) state: %d means failed , ignore", tx.Hash().String(), receipt.Status)
		return nil, nil
	}
	p := evm.NewSmartContractLogParser(e.isToValidContractAddress,
		e.getAssetFromTokenAddress,
		e.getTokenDecimalsForTHORChain,
		e.convertAmount,
		e.vaultABI,
		common.ETHAsset,
		maxLogs)
	// txInItem will be changed in p.GetTxInItem function, so if the function return an error
	// txInItem should be abandoned
	if _, err = p.GetTxInItem(receipt.Logs, txInItem); err != nil {
		return nil, fmt.Errorf("fail to parse logs, err: %w", err)
	}
	// under no circumstance ETH gas price will be less than 1 Gwei , unless it is in dev environment
	txGasPrice := receipt.EffectiveGasPrice

	e.logger.Debug().Msgf("tx: %s, gas price: %s, gas used: %d,receipt status:%d", txInItem.Tx, txGasPrice.String(), receipt.GasUsed, receipt.Status)

	txInItem.Gas = common.MakeEVMGas(common.ETHChain, txGasPrice, receipt.GasUsed, nil)
	if txInItem.Coins.IsEmpty() {
		e.logger.Debug().Msgf("there is no coin in this tx, ignore, %+v", txInItem)
		return nil, nil
	}
	e.logger.Debug().Msgf("tx in item: %+v", txInItem)
	return txInItem, nil
}

func (e *ETHScanner) getTxInFromTransaction(tx *etypes.Transaction, receipt *etypes.Receipt) (*stypes.TxInItem, error) {
	txInItem := &stypes.TxInItem{
		Tx: tx.Hash().Hex()[2:],
	}
	asset := common.ETHAsset
	sender, err := e.eipSigner.Sender(tx)
	if err != nil {
		return nil, fmt.Errorf("fail to get sender: %w", err)
	}
	txInItem.Sender = strings.ToLower(sender.String())
	txInItem.To = strings.ToLower(tx.To().String())
	// this is native , thus memo is data field
	data := tx.Data()
	if len(data) > 0 {
		var memo []byte
		memo, err = hex.DecodeString(string(data))
		if err != nil {
			txInItem.Memo = string(data)
		} else {
			txInItem.Memo = string(memo)
		}
	}
	ethValue := e.convertAmount(ethToken, tx.Value())
	txInItem.Coins = append(txInItem.Coins, common.NewCoin(asset, ethValue))
	txGasPrice := receipt.EffectiveGasPrice

	txInItem.Gas = common.MakeEVMGas(common.ETHChain, txGasPrice, receipt.GasUsed, nil)
	if txInItem.Coins.IsEmpty() {
		if txInItem.Sender == txInItem.To {
			// When the Sender and To is the same then there's no balance chance whatever the Coins,
			// and for Tx-received Valid() a non-zero Amount is needed to observe
			// the transaction fees (THORChain gas cost) of unstuck.go's cancel transactions.
			observableAmount := common.ETHChain.DustThreshold()
			txInItem.Coins = common.NewCoins(common.NewCoin(common.ETHAsset, observableAmount))

			// remove the outbound from signer cache so it can be re-attempted
			if e.signerCacheManager != nil {
				e.signerCacheManager.RemoveSigned(tx.Hash().Hex())
			}
		} else {
			e.logger.Debug().Msgf("there is no coin in this tx, ignore, %+v", txInItem)
			return nil, nil
		}
	}
	return txInItem, nil
}

func (e *ETHScanner) fromTxToTxIn(tx *etypes.Transaction) (*stypes.TxInItem, error) {
	if tx == nil || tx.To() == nil {
		return nil, nil
	}
	receipt, err := e.getReceipt(tx.Hash().Hex())
	if err != nil {
		if errors.Is(err, ethereum.NotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("fail to get transaction receipt: %w", err)
	}
	if receipt.Status != 1 {
		// a transaction that is failed
		// remove the Signer cache , so the tx out item can be retried
		if e.signerCacheManager != nil {
			e.signerCacheManager.RemoveSigned(tx.Hash().String())
		}
		e.logger.Debug().Msgf("tx(%s) state: %d means failed , ignore", tx.Hash().String(), receipt.Status)
		return e.getTxInFromFailedTransaction(tx, receipt), nil
	}

	disableWhitelist, err := e.bridge.GetMimir(constants.EVMDisableContractWhitelist.String())
	if err != nil {
		e.logger.Err(err).Msgf("fail to get %s", constants.EVMDisableContractWhitelist.String())
		disableWhitelist = 0
	}

	if disableWhitelist == 1 {
		// parse tx without whitelist
		destination := tx.To()
		isToVault, _ := e.pubkeyMgr.IsValidPoolAddress(destination.String(), e.cfg.ChainID)

		switch {
		case isToVault:
			// Tx to a vault
			return e.getTxInFromTransaction(tx, receipt)
		case e.isToValidContractAddress(destination, true):
			// Deposit directly to router
			return e.getTxInFromSmartContract(tx, receipt, 0)
		case evm.IsSmartContractCall(tx, receipt):
			// Tx to a different contract, attempt to parse with max allowable logs
			return e.getTxInFromSmartContract(tx, receipt, int64(e.cfg.MaxContractTxLogs))
		default:
			// Tx to a non-contract or vault address
			return e.getTxInFromTransaction(tx, receipt)
		}
	} else {
		// parse tx with whitelist
		if e.isToValidContractAddress(tx.To(), true) {
			return e.getTxInFromSmartContract(tx, receipt, 0)
		}
		return e.getTxInFromTransaction(tx, receipt)
	}
}

// getTxInFromFailedTransaction when a transaction failed due to out of gas, this method will check whether the transaction is an outbound
// it fake a txInItem if the failed transaction is an outbound , and report it back to THORNode , thus the gas fee can be subsidised
// need to know that this will also cause the vault that send out the outbound to be slashed 1.5x gas
// it is for security purpose
func (e *ETHScanner) getTxInFromFailedTransaction(tx *etypes.Transaction, receipt *etypes.Receipt) *stypes.TxInItem {
	if receipt.Status == 1 {
		e.logger.Info().Str("hash", tx.Hash().String()).Msg("success transaction should not get into getTxInFromFailedTransaction")
		return nil
	}
	fromAddr, err := e.eipSigner.Sender(tx)
	if err != nil {
		e.logger.Err(err).Msg("fail to get from address")
		return nil
	}
	ok, cif := e.pubkeyMgr.IsValidPoolAddress(fromAddr.String(), common.ETHChain)
	if !ok || cif.IsEmpty() {
		return nil
	}
	txGasPrice := receipt.EffectiveGasPrice
	txHash := tx.Hash().Hex()[2:]
	return &stypes.TxInItem{
		Tx:     txHash,
		Memo:   memo.NewOutboundMemo(common.TxID(txHash)).String(),
		Sender: strings.ToLower(fromAddr.String()),
		To:     strings.ToLower(tx.To().String()),
		Coins:  common.NewCoins(common.NewCoin(common.ETHAsset, cosmos.NewUint(1))),
		Gas:    common.MakeEVMGas(common.ETHChain, txGasPrice, receipt.GasUsed, nil),
	}
}
