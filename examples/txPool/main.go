package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	common2 "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	ontology_go_sdk "github.com/ontio/ontology-go-sdk"
	"github.com/ontio/ontology-go-sdk/oep4"
	"github.com/ontio/ontology/cmd/utils"
	"github.com/ontio/ontology/common"
	"github.com/ontio/ontology/common/log"
	"github.com/ontio/ontology/core/payload"
	types2 "github.com/ontio/ontology/core/types"
	"io/ioutil"
	"math/big"
	"math/rand"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

const WingABI = "[{\"inputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"constructor\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"owner\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"spender\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"value\",\"type\":\"uint256\"}],\"name\":\"Approval\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"previousOwner\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"newOwner\",\"type\":\"address\"}],\"name\":\"OwnershipTransferred\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"from\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"to\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"value\",\"type\":\"uint256\"}],\"name\":\"Transfer\",\"type\":\"event\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"owner\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"spender\",\"type\":\"address\"}],\"name\":\"allowance\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"spender\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"}],\"name\":\"approve\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"account\",\"type\":\"address\"}],\"name\":\"balanceOf\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"spender\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"subtractedValue\",\"type\":\"uint256\"}],\"name\":\"decreaseAllowance\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"spender\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"addedValue\",\"type\":\"uint256\"}],\"name\":\"increaseAllowance\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"name\",\"outputs\":[{\"internalType\":\"string\",\"name\":\"\",\"type\":\"string\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"owner\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"renounceOwnership\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"symbol\",\"outputs\":[{\"internalType\":\"string\",\"name\":\"\",\"type\":\"string\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"totalSupply\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"recipient\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"}],\"name\":\"transfer\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"sender\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"recipient\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"}],\"name\":\"transferFrom\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"newOwner\",\"type\":\"address\"}],\"name\":\"transferOwnership\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"decimals\",\"outputs\":[{\"internalType\":\"uint8\",\"name\":\"\",\"type\":\"uint8\"}],\"stateMutability\":\"pure\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"to\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"}],\"name\":\"mint\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"}],\"name\":\"burn\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]"

var gasPrice, gasLimit uint64
var testPrivateKey *ecdsa.PrivateKey
var chainId int64

func main() {
	chainId = 12345
	gasPrice = 0
	gasLimit = 20800000
	sdk := ontology_go_sdk.NewOntologySdk()
	testNet := "http://172.168.3.73:20336"
	testNet = "http://127.0.0.1:20336"
	//testNet = "http://192.168.0.189:20336"

	sdk.NewRpcClient().SetAddress(testNet)

	testNet = "http://172.168.3.73:20339"
	testNet = "http://127.0.0.1:20339"
	//testNet = "http://192.168.0.189:20339"
	ethClient, err := ethclient.Dial(testNet)
	checkErr(err)

	if false {
		createWallet(sdk)
		return
	}
	wallet, err := sdk.OpenWallet("txpool.dat")
	checkErr(err)
	acct, err := wallet.GetAccountByAddress("ANwj1AC4gUarPbw8sD3AenazMDv1gXFtqr", []byte("server"))
	checkErr(err)
	testPrivateKeyStr := "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
	testPrivateKey, err = crypto.HexToECDSA(testPrivateKeyStr)
	checkErr(err)
	testEthAddr := crypto.PubkeyToAddress(testPrivateKey.PublicKey)
	testEthAddrOnt := common.Address(testEthAddr)
	log.Infof("testEthAddrOnt: %s", testEthAddrOnt.ToBase58())
	if false {
		//peiwen, _ := common.AddressFromBase58("AVTh2TX6vBVhSPvNoBhG7rqPkvUVWb2WDS")
		txhash, err := sdk.Native.Ong.Transfer(gasPrice, gasLimit, acct, acct, common.Address(testEthAddr), 10000*1000000000)
		checkErr(err)
		fmt.Println(txhash.ToHexString())
		return
	}

	oep4Addr, erc20Addr := deployContract(sdk, ethClient, acct, testPrivateKey)
	log.Infof("oep4Addr: %s", oep4Addr.ToHexString())
	initContract(sdk, acct, oep4Addr)

	toAddr, _ := common.AddressFromBase58("AHNtib2FYwhdTQZc9oKKrR3M2MyYH8NrL9")

	exit := make(chan bool, 0)
	checkTxQueue := make(chan CheckTx, 10000)
	startCheckTxTask(sdk, checkTxQueue, true, exit)

	// 正常交易压力测试
	txNums := 1
	if true {
		testStress(sdk, acct, toAddr, oep4Addr, txNums, ethClient, testEthAddr, erc20Addr, checkTxQueue)
	}

	// 相同的txNonce交易  交易手续费大的应该成功
	if false {
		testNonce(ethClient, testEthAddr, erc20Addr, common2.Address(toAddr), checkTxQueue, txNums)
	}
	<-exit
}

func testStress(sdk *ontology_go_sdk.OntologySdk, acct *ontology_go_sdk.Account, toAddr, oep4Addr common.Address,
	l int, ethClient *ethclient.Client, testEthAddr, erc20Addr common2.Address, checkTxQueue chan CheckTx) {
	oep4Txs := genOep4Tx(sdk, acct, toAddr, oep4Addr, l)
	txNonce := getTxNonce(ethClient, testEthAddr)
	log.Infof("txNonce: %d", txNonce)
	erc20Txs := genErc20TransferTxs(l, txNonce, erc20Addr, ontAddrToEthAddr(toAddr))

	for i := 0; i < l; i++ {
		txHash, err := sdk.SendTransaction(oep4Txs[i])
		checkErr(err)
		checkTxQueue <- NewCheckTx("oep4", txHash, 1)
		err = ethClient.SendTransaction(context.Background(), erc20Txs[i])
		checkErr(err)
		checkTxQueue <- NewCheckTx("erc20", common.Uint256(erc20Txs[i].Hash()), 1)
	}
}

func testNonce(ethClient *ethclient.Client, testEthAddr, erc20Addr, toAddr common2.Address, checkTxQueue chan CheckTx, l int) {
	txNonce := getTxNonce(ethClient, testEthAddr)
	log.Infof("txNonce: %d", txNonce)
	for i := 0; i < l; i++ {
		erc20Tx := genErc20TransferTx(txNonce, int64(gasPrice), erc20Addr, toAddr, big.NewInt(1000))
		erc20Tx2 := genErc20TransferTx(txNonce, int64(gasPrice+10), erc20Addr, toAddr, big.NewInt(2000))
		thash := common.Uint256(erc20Tx.Hash())
		log.Infof("erc20Tx:", thash.ToHexString())
		err := ethClient.SendTransaction(context.Background(), erc20Tx)
		thash = common.Uint256(erc20Tx2.Hash())
		log.Infof("erc20Tx2:", thash.ToHexString())
		checkErr(err)
		checkTxQueue <- NewCheckTx("erc20", common.Uint256(erc20Tx.Hash()), 0)
		//err = ethClient.SendTransaction(context.Background(), erc20Tx2)
		//checkErr(err)
		//checkTxQueue <- NewCheckTx("erc20", common.Uint256(erc20Tx2.Hash()), 1)
		txNonce++
	}
}

type CheckTx struct {
	txType      string
	txHash      common.Uint256
	expectState byte
}

func NewCheckTx(txType string, txHash common.Uint256, expectState byte) CheckTx {
	return CheckTx{
		txType:      txType,
		txHash:      txHash,
		expectState: expectState,
	}
}

func getTxNonce(ethClient *ethclient.Client, addr common2.Address) uint64 {
	txNonce, err := ethClient.PendingNonceAt(context.Background(), addr)
	checkErr(err)
	return txNonce
}

func waitToExit() {
	exit := make(chan bool, 0)
	sc := make(chan os.Signal, 1)
	signal.Notify(sc, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		for sig := range sc {
			log.Infof("received exit signal: %v.", sig.String())

			close(exit)
			break
		}
	}()
	<-exit
}

func createWallet(sdk *ontology_go_sdk.OntologySdk) {
	wallet, err := sdk.OpenWallet("txpool.dat")
	checkErr(err)
	pwd := []byte("server")
	for i := 0; i < 2; i++ {
		acct, err := wallet.NewDefaultSettingAccount(pwd)
		checkErr(err)
		log.Infof("address:%s", acct.Address.ToBase58())
	}
	wallet.Save()
}

func startCheckTxTask(sdk *ontology_go_sdk.OntologySdk, checkTxQueue chan CheckTx, support bool, exit chan bool) {
	go func() {
		for checkTx := range checkTxQueue {
			// 暂时不用
			if !support {
				continue
			}
			for {
				evt, err := sdk.GetSmartContractEvent(checkTx.txHash.ToHexString())
				if evt != nil {
					if evt.State != checkTx.expectState {
						log.Infof("expect state: %d, actual state: %d", checkTx.expectState, evt.State)
						panic(checkTx.txHash.ToHexString())
					} else {
						log.Infof("check tx success,txType: %s, txhash: %s", checkTx.txType, checkTx.txHash.ToHexString())
						break
					}
				} else {
					if err != nil {
						log.Errorf("txType: %s, txhash: %s, err: %s", checkTx.txType, checkTx.txHash.ToHexString(), err)
					}
					log.Infof("wait tx, txType: %s, txhash: %s", checkTx.txType, checkTx.txHash.ToHexString())
					time.Sleep(3 * time.Second)
					continue
				}
			}
		}
		exit <- true
	}()
}

func initContract(sdk *ontology_go_sdk.OntologySdk, acct *ontology_go_sdk.Account, oep4Addr common.Address) {
	oo := oep4.NewOep4(oep4Addr, sdk)
	res, err := oo.BalanceOf(acct.Address)
	checkErr(err)
	if res.Uint64() == 0 {
		_, err = sdk.NeoVM.InvokeNeoVMContract(gasPrice, gasLimit, acct, acct, oep4Addr,
			[]interface{}{"init", []interface{}{acct.Address}})
		checkErr(err)
		sdk.WaitForGenerateBlock(time.Second*40, 1)
	}
}

func ontAddrToEthAddr(ontAddr common.Address) common2.Address {
	return common2.BytesToAddress(ontAddr[:])
}

func genErc20TransferTxs(l int, txNonce uint64, contractAddr common2.Address, toAddr common2.Address) []*types.Transaction {
	erc20Txs := make([]*types.Transaction, 0)
	rand.Seed(time.Now().Unix())
	for i := 0; i < l; i++ {
		amt := rand.Int63n(10000)
		erc20Tx := genErc20TransferTx(txNonce, int64(gasPrice), contractAddr, toAddr, big.NewInt(amt))
		erc20Txs = append(erc20Txs, erc20Tx)
		txNonce++
	}
	return erc20Txs
}

func genErc20TransferTx(txNonce uint64, gasPrice int64, contractAddr common2.Address, toAddr common2.Address, amt *big.Int) *types.Transaction {
	erc20Tx, err := GenEVMTx(txNonce, gasPrice, contractAddr, "transfer", toAddr, amt)
	checkErr(err)
	return erc20Tx
}

func GenEVMTx(nonce uint64, gasPrice int64, contractAddr common2.Address, method string, params ...interface{}) (*types.Transaction, error) {
	chainId := big.NewInt(chainId)
	opts, err := bind.NewKeyedTransactorWithChainID(testPrivateKey, chainId)
	opts.GasPrice = big.NewInt(gasPrice) // 1Gwei
	opts.Nonce = big.NewInt(int64(nonce))
	opts.GasLimit = gasLimit

	checkErr(err)
	parsed, err := abi.JSON(strings.NewReader(WingABI))
	checkErr(err)
	input, err := parsed.Pack(method, params...)
	deployTx := types.NewTransaction(opts.Nonce.Uint64(), contractAddr, opts.Value, opts.GasLimit, opts.GasPrice, input)
	signedTx, err := opts.Signer(opts.From, deployTx)
	checkErr(err)
	return signedTx, err
}

func genOep4Tx(sdk *ontology_go_sdk.OntologySdk, acct *ontology_go_sdk.Account, toAddr, oep4Addr common.Address, l int) []*types2.MutableTransaction {
	rand.Seed(time.Now().Unix())
	oep4Txs := make([]*types2.MutableTransaction, 0)
	for i := 0; i < l; i++ {
		amt := rand.Int63n(1000)
		params := []interface{}{"transfer", []interface{}{acct.Address, toAddr, amt}}
		tx, err := sdk.NeoVM.NewNeoVMInvokeTransaction(gasPrice, gasLimit, oep4Addr, params)
		checkErr(err)
		err = sdk.SignToTransaction(tx, acct)
		checkErr(err)
		oep4Txs = append(oep4Txs, tx)
	}
	return oep4Txs
}

func deployContract(sdk *ontology_go_sdk.OntologySdk, ethClient *ethclient.Client, acct *ontology_go_sdk.Account,
	testPrivateKey *ecdsa.PrivateKey) (common.Address, common2.Address) {
	oep4Code := loadContract("examples/txPool/test-contract/WingToken.avm")
	erc20Code := loadContract("examples/txPool/test-contract/wing_eth.evm")

	oep4Addr := common.AddressFromVmCode(oep4Code)
	pc, err := sdk.GetSmartContract(oep4Addr.ToHexString())
	if pc == nil || err != nil {
		tx, err := NewDeployNeoContract(sdk, acct, oep4Code)
		checkErr(err)
		mutTx, err := tx.IntoMutable()
		checkErr(err)
		txHash, err := sdk.SendTransaction(mutTx)
		checkErr(err)
		log.Infof("deploy oep4 txHash: %s", txHash.ToHexString())
		sdk.WaitForGenerateBlock(time.Second*40, 1)
	}
	testEthAddr := crypto.PubkeyToAddress(testPrivateKey.PublicKey)
	ethAddr := crypto.CreateAddress(testEthAddr, 0)

	code, err := ethClient.CodeAt(context.Background(), ethAddr, nil)
	if code == nil || err != nil {
		opts, err := bind.NewKeyedTransactorWithChainID(testPrivateKey, big.NewInt(chainId))
		opts.GasPrice = big.NewInt(int64(gasPrice))
		opts.Nonce = big.NewInt(0)
		opts.GasLimit = 8000000
		ethTx, err := NewDeployEvmContract(opts, erc20Code, WingABI)
		checkErr(err)
		err = ethClient.SendTransaction(context.Background(), ethTx)
		checkErr(err)
		txHash := common.Uint256(ethTx.Hash())
		log.Infof("deploy erc20 txHash: %s", txHash.ToHexString())
		sdk.WaitForGenerateBlock(time.Second*40, 1)
	}
	return oep4Addr, ethAddr
}

func NewDeployEvmContract(opts *bind.TransactOpts, code []byte, jsonABI string, params ...interface{}) (*types.Transaction, error) {
	parsed, err := abi.JSON(strings.NewReader(jsonABI))
	checkErr(err)
	input, err := parsed.Pack("", params...)
	checkErr(err)
	input = append(code, input...)
	deployTx := types.NewContractCreation(opts.Nonce.Uint64(), opts.Value, opts.GasLimit, opts.GasPrice, input)
	signedTx, err := opts.Signer(opts.From, deployTx)
	checkErr(err)
	return signedTx, err
}

func NewDeployNeoContract(sdk *ontology_go_sdk.OntologySdk, signer *ontology_go_sdk.Account, code []byte) (*types2.Transaction, error) {
	mutable, err := utils.NewDeployCodeTransaction(gasPrice, gasLimit, code, payload.NEOVM_TYPE, "name", "version",
		"author", "email", "desc")
	if err != nil {
		return nil, err
	}
	sdk.SignToTransaction(mutable, signer)
	tx, err := mutable.IntoImmutable()
	return tx, err
}

func loadContract(filePath string) []byte {
	if common.FileExisted(filePath) {
		raw, err := ioutil.ReadFile(filePath)
		checkErr(err)
		ss := strings.ReplaceAll(string(raw), "\n", "")
		ss = strings.ReplaceAll(ss, " ", "")
		code, err := hex.DecodeString(ss)
		if err != nil {
			return raw
		} else {
			return code
		}
	} else {
		panic("no existed file:" + filePath)
	}
}

func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}
