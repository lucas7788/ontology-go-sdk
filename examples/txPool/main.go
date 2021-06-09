package main

import (
	"crypto/ecdsa"
	"encoding/hex"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	common2 "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	ontology_go_sdk "github.com/ontio/ontology-go-sdk"
	"github.com/ontio/ontology/cmd/utils"
	"github.com/ontio/ontology/common"
	"github.com/ontio/ontology/common/log"
	"github.com/ontio/ontology/core/payload"
	types2 "github.com/ontio/ontology/core/types"
	"io/ioutil"
	"math/big"
	"math/rand"
	"strings"
	"time"
)

const WingABI = "[{\"inputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"constructor\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"owner\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"spender\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"value\",\"type\":\"uint256\"}],\"name\":\"Approval\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"previousOwner\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"newOwner\",\"type\":\"address\"}],\"name\":\"OwnershipTransferred\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"from\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"to\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"value\",\"type\":\"uint256\"}],\"name\":\"Transfer\",\"type\":\"event\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"owner\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"spender\",\"type\":\"address\"}],\"name\":\"allowance\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"spender\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"}],\"name\":\"approve\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"account\",\"type\":\"address\"}],\"name\":\"balanceOf\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"spender\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"subtractedValue\",\"type\":\"uint256\"}],\"name\":\"decreaseAllowance\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"spender\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"addedValue\",\"type\":\"uint256\"}],\"name\":\"increaseAllowance\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"name\",\"outputs\":[{\"internalType\":\"string\",\"name\":\"\",\"type\":\"string\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"owner\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"renounceOwnership\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"symbol\",\"outputs\":[{\"internalType\":\"string\",\"name\":\"\",\"type\":\"string\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"totalSupply\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"recipient\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"}],\"name\":\"transfer\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"sender\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"recipient\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"}],\"name\":\"transferFrom\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"newOwner\",\"type\":\"address\"}],\"name\":\"transferOwnership\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"decimals\",\"outputs\":[{\"internalType\":\"uint8\",\"name\":\"\",\"type\":\"uint8\"}],\"stateMutability\":\"pure\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"to\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"}],\"name\":\"mint\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"}],\"name\":\"burn\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]"

var gasPrice, gasLimit uint64
var testPrivateKey *ecdsa.PrivateKey

type CheckTx struct {
	txHash      common.Uint256
	expectState byte
}

func NewCheckTx(txHash common.Uint256, expectState byte) CheckTx {
	return CheckTx{
		txHash:      txHash,
		expectState: expectState,
	}
}

func main() {
	sdk := ontology_go_sdk.NewOntologySdk()
	sdk.NewRpcClient().SetAddress("http://127.0.0.1:20336")
	if false {
		createWallet(sdk)
		return
	}
	wallet, err := sdk.OpenWallet("txpool.dat")
	checkErr(err)
	acct, err := wallet.GetAccountByAddress("AWCgtHfJywHRCBCJUXix3XH2xJAhPYYU6j", []byte("111111"))
	checkErr(err)
	testPrivateKeyStr := "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
	testPrivateKey, err := crypto.HexToECDSA(testPrivateKeyStr)
	checkErr(err)
	oep4Addr, erc20Addr := deployContract(sdk, acct, testPrivateKey)
	initContract(sdk, acct, oep4Addr)

	toAddr, _ := common.AddressFromBase58("ASZVKmGCjMJhirNsh7ENyGGXicEPECfcmy")

	checkTxQueue := make(chan CheckTx, 10000)
	startCheckTxTask(sdk, checkTxQueue, false)

	// 正常交易压力测试
	l := 10
	oep4Tx := genOep4Tx(sdk, acct, toAddr, oep4Addr, l)
	txNonce := 1
	erc20Txs := genErc20TransferTxs(l, txNonce, erc20Addr, ontAddrToEthAddr(toAddr))
	txNonce += l
	for i := 0; i < l; i++ {
		txHash, err := sdk.SendTransaction(oep4Tx[i])
		checkErr(err)
		checkTxQueue <- NewCheckTx(txHash, 1)
		txHash, err = sdk.SendTransaction(erc20Txs[i])
		checkErr(err)
		checkTxQueue <- NewCheckTx(txHash, 1)
	}
	// 相同的txNonce交易  交易手续费大的应该成功
	for i := 0; i < l; i++ {
		erc20Tx := genErc20TransferTx(txNonce, erc20Addr, ontAddrToEthAddr(toAddr), big.NewInt(1000))
		erc20Tx2 := genErc20TransferTx(txNonce, erc20Addr, ontAddrToEthAddr(toAddr), big.NewInt(2000))
		erc20Tx2.GasPrice = erc20Tx.GasPrice + 10
		txHash, err := sdk.SendTransaction(erc20Tx)
		checkErr(err)
		checkTxQueue <- NewCheckTx(txHash, 0)
		txHash, err = sdk.SendTransaction(erc20Tx2)
		checkErr(err)
		checkTxQueue <- NewCheckTx(txHash, 1)
		txNonce++
	}
}

func createWallet(sdk *ontology_go_sdk.OntologySdk) {
	wallet, err := sdk.CreateWallet("txpool.dat")
	checkErr(err)
	pwd := []byte("111111")
	for i := 0; i < 2; i++ {
		acct, err := wallet.NewDefaultSettingAccount(pwd)
		checkErr(err)
		log.Infof("address:%s", acct.Address.ToBase58())
	}
	wallet.Save()
}

func startCheckTxTask(sdk *ontology_go_sdk.OntologySdk, checkTxQueue chan CheckTx, support bool) {
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
						panic(checkTx.txHash.ToHexString())
					} else {
						break
					}
				} else {
					if err != nil {
						log.Errorf("txhash: %s, err: %s", checkTx.txHash.ToHexString(), err)
					}
					time.Sleep(3 * time.Second)
					continue
				}
			}
		}
	}()
}

func initContract(sdk *ontology_go_sdk.OntologySdk, acct *ontology_go_sdk.Account, oep4Addr common.Address) {
	gasPrice := uint64(0)
	gasLimit := uint64(20000)
	_, err := sdk.NeoVM.InvokeNeoVMContract(gasPrice, gasLimit, acct, acct, oep4Addr,
		[]interface{}{"init", []interface{}{}})
	checkErr(err)
	sdk.WaitForGenerateBlock(time.Second*40, 1)
}

func ontAddrToEthAddr(ontAddr common.Address) common2.Address {
	return common2.BytesToAddress(ontAddr[:])
}

func genErc20TransferTxs(l int, txNonce int, contractAddr common2.Address, toAddr common2.Address) []*types2.MutableTransaction {
	erc20Txs := make([]*types2.MutableTransaction, 0)
	rand.Seed(time.Now().Unix())
	for i := 0; i < l; i++ {
		amt := rand.Int63n(10000)
		erc20Tx := genErc20TransferTx(txNonce, contractAddr, toAddr, big.NewInt(amt))
		erc20Txs = append(erc20Txs, erc20Tx)
		txNonce++
	}
	return erc20Txs
}
func genErc20TransferTx(txNonce int, contractAddr common2.Address, toAddr common2.Address, amt *big.Int) *types2.MutableTransaction {
	erc20Tx, err := GenEVMTx(txNonce, contractAddr, "transfer", toAddr, amt)
	checkErr(err)
	tx, err := types2.TransactionFromEIP155(erc20Tx)
	checkErr(err)
	mutTx, err := tx.IntoMutable()
	checkErr(err)
	return mutTx
}

func GenEVMTx(nonce int, contractAddr common2.Address, method string, params ...interface{}) (*types.Transaction, error) {
	chainId := big.NewInt(5851)
	opts, err := bind.NewKeyedTransactorWithChainID(testPrivateKey, chainId)
	opts.GasPrice = big.NewInt(1000000000) // 1Gwei
	opts.Nonce = big.NewInt(int64(nonce))
	opts.GasLimit = 8000000

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

func deployContract(sdk *ontology_go_sdk.OntologySdk, acct *ontology_go_sdk.Account, testPrivateKey *ecdsa.PrivateKey) (common.Address, common2.Address) {
	oep4Code := loadContract("./test-contract/oep4_example.py")
	erc20Code := loadContract("./test-contract/wing_eth.evm")
	tx, err := NewDeployNeoContract(sdk, acct, oep4Code)
	checkErr(err)
	mutTx, err := tx.IntoMutable()
	checkErr(err)
	txHash, err := sdk.SendTransaction(mutTx)
	log.Infof("deploy oep4 txHash: %s", txHash.ToHexString())
	oep4Addr := common.AddressFromVmCode(oep4Code)
	chainId := big.NewInt(5851)
	opts, err := bind.NewKeyedTransactorWithChainID(testPrivateKey, chainId)
	opts.GasPrice = big.NewInt(0)
	opts.Nonce = big.NewInt(0)
	opts.GasLimit = 8000000
	ethTx, err := NewDeployEvmContract(opts, erc20Code, WingABI)
	checkErr(err)
	tx, err = types2.TransactionFromEIP155(ethTx)
	checkErr(err)
	mutTx, err = tx.IntoMutable()
	checkErr(err)
	txHash, err = sdk.SendTransaction(mutTx)
	log.Infof("deploy erc20 txHash: %s", txHash.ToHexString())
	testEthAddr := crypto.PubkeyToAddress(testPrivateKey.PublicKey)
	ethAddr := crypto.CreateAddress(testEthAddr, 0)
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
	mutable, err := utils.NewDeployCodeTransaction(0, 100000000, code, payload.NEOVM_TYPE, "name", "version",
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
		code, err := hex.DecodeString(string(raw))
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
