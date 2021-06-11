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
	"strings"
	"time"
)

const WingABI = "[{\"inputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"constructor\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"owner\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"spender\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"value\",\"type\":\"uint256\"}],\"name\":\"Approval\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"previousOwner\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"newOwner\",\"type\":\"address\"}],\"name\":\"OwnershipTransferred\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"from\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"to\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"value\",\"type\":\"uint256\"}],\"name\":\"Transfer\",\"type\":\"event\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"owner\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"spender\",\"type\":\"address\"}],\"name\":\"allowance\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"spender\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"}],\"name\":\"approve\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"account\",\"type\":\"address\"}],\"name\":\"balanceOf\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"spender\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"subtractedValue\",\"type\":\"uint256\"}],\"name\":\"decreaseAllowance\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"spender\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"addedValue\",\"type\":\"uint256\"}],\"name\":\"increaseAllowance\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"name\",\"outputs\":[{\"internalType\":\"string\",\"name\":\"\",\"type\":\"string\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"owner\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"renounceOwnership\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"symbol\",\"outputs\":[{\"internalType\":\"string\",\"name\":\"\",\"type\":\"string\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"totalSupply\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"recipient\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"}],\"name\":\"transfer\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"sender\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"recipient\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"}],\"name\":\"transferFrom\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"newOwner\",\"type\":\"address\"}],\"name\":\"transferOwnership\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"decimals\",\"outputs\":[{\"internalType\":\"uint8\",\"name\":\"\",\"type\":\"uint8\"}],\"stateMutability\":\"pure\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"to\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"}],\"name\":\"mint\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"}],\"name\":\"burn\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]"

var gasPrice, gasLimit uint64
var testPrivateKey *ecdsa.PrivateKey
var chainId int64

func main() {
	chainId = 12345
	gasPrice = 500
	gasLimit = 20800000
	sdk := ontology_go_sdk.NewOntologySdk()
	testNet := "http://172.168.3.73:20336"
	//testNet = "http://127.0.0.1:20336"
	//testNet = "http://192.168.0.189:20336"

	sdk.NewRpcClient().SetAddress(testNet)

	testNet = "http://172.168.3.73:20339"
	//testNet = "http://127.0.0.1:20339"
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
		wallet2,err := sdk.OpenWallet("rongyi.dat")
		checkErr(err)
		rongyi,err := wallet2.GetAccountByAddress("ANwj1AC4gUarPbw8sD3AenazMDv1gXFtqr", []byte("server"))
		checkErr(err)
		//peiwen, _ := common.AddressFromBase58("AVTh2TX6vBVhSPvNoBhG7rqPkvUVWb2WDS")
		//txhash, err := sdk.Native.Ong.Transfer(gasPrice, gasLimit, rongyi, rongyi, common.Address(testEthAddr), 10000*1000000000)
		txhash, err := sdk.Native.Ong.Transfer(gasPrice, gasLimit, rongyi, rongyi, acct.Address, 10000*1000000000)
		checkErr(err)
		fmt.Println(txhash.ToHexString())
		return
	}

	oep4Addr, erc20Addr := deployContract(sdk, ethClient, acct, testPrivateKey)
	log.Infof("oep4Addr: %s", oep4Addr.ToHexString())

	exit := make(chan bool, 0)
	checkTxQueue := make(chan CheckTx, 10000)
	startCheckTxTask(sdk, checkTxQueue, true, exit)

	acctNum := 10
	accts := genAccts(sdk, wallet, acctNum, acct, oep4Addr)
	ethKeys := genEthPrivateKey(acctNum, testPrivateKey, ethClient, erc20Addr, sdk)

	// 正常交易压力测试
	txNums := 10
	if true {
		testStress(sdk, acct, accts, oep4Addr, txNums, ethClient, ethKeys, erc20Addr, checkTxQueue)
	}

	// 相同的txNonce交易  交易手续费大的应该成功
	if false {
		testNonce(ethClient, erc20Addr, ethKeys, checkTxQueue, txNums)
	}
	close(checkTxQueue)
	<-exit
	log.Info("*************** test end ******************")
}

func testStress(sdk *ontology_go_sdk.OntologySdk, acct *ontology_go_sdk.Account, accts []*ontology_go_sdk.Account,
	oep4Addr common.Address, txNum int, ethClient *ethclient.Client, ethKeys []*EthKey, erc20Addr common2.Address,
	checkTxQueue chan CheckTx) {
	oep4Txs := genOep4Tx(sdk, acct, accts, oep4Addr, txNum)

	erc20Txs := genErc20TransferTxs(txNum, erc20Addr, ethKeys)

	for i := 0; i < txNum; i++ {
		txHash, err := sdk.SendTransaction(oep4Txs[i])
		checkErr(err)
		checkTxQueue <- NewCheckTx("oep4", txHash, 1)
		err = ethClient.SendTransaction(context.Background(), erc20Txs[i])
		checkErr(err)
		checkTxQueue <- NewCheckTx("erc20", common.Uint256(erc20Txs[i].Hash()), 1)
	}
}

func testNonce(ethClient *ethclient.Client, erc20Addr common2.Address, ethKeys []*EthKey, checkTxQueue chan CheckTx, txNum int) {

	l := len(ethKeys)
	var ind, ind2 int
	var from *EthKey
	var toAddr common2.Address
	for i := 0; i < txNum; i++ {
		ind = i % l
		ind2 = (i + 1) % l
		from = ethKeys[ind]
		toAddr = ethKeys[ind2].addr
		erc20Tx := genErc20TransferTx(int64(gasPrice), erc20Addr, from, toAddr, big.NewInt(1000))
		erc20Tx2 := genErc20TransferTx(int64(gasPrice+10), erc20Addr, from, toAddr, big.NewInt(2000))
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
		from.nonce++
	}
}

func genAccts(sdk *ontology_go_sdk.OntologySdk, wallet *ontology_go_sdk.Wallet, acctNum int, acct *ontology_go_sdk.Account, oep4Addr common.Address) []*ontology_go_sdk.Account {
	accts := make([]*ontology_go_sdk.Account, 0)
	accts = append(accts, acct)
	balance, err := sdk.Native.Ong.BalanceOf(acct.Address)
	checkErr(err)
	unit := balance / uint64(acctNum*10)
	token := oep4.NewOep4(oep4Addr, sdk)
	oBalance, err := token.BalanceOf(acct.Address)
	checkErr(err)
	unit2 := new(big.Int).Div(oBalance, big.NewInt(int64(acctNum*10)))
	var acct2 *ontology_go_sdk.Account
	for i := 0; i < acctNum; i++ {
		acct2, err = wallet.NewDefaultSettingAccount([]byte("111111"))
		checkErr(err)
		if unit > 0 {
			_, err = sdk.Native.Ong.Transfer(gasPrice, gasLimit, acct, acct, acct2.Address, unit)
			checkErr(err)
		}
		if unit2.Uint64() > 0 {
			_, err = token.Transfer(acct, acct2.Address, unit2, acct, gasPrice, gasLimit)
			checkErr(err)
		}
		accts = append(accts, acct)
	}
	sdk.WaitForGenerateBlock(time.Second*40, 2)
	return accts
}

type EthKey struct {
	key   *ecdsa.PrivateKey
	addr  common2.Address
	nonce uint64
}

func genEthPrivateKey(acctNum int, first *ecdsa.PrivateKey, ethClient *ethclient.Client, erc20Addr common2.Address, sdk *ontology_go_sdk.OntologySdk) []*EthKey {
	ks := make([]*EthKey, 0)
	addr := crypto.PubkeyToAddress(first.PublicKey)
	nonce, err := ethClient.PendingNonceAt(context.Background(), addr)
	checkErr(err)
	firstKey := &EthKey{
		key:   testPrivateKey,
		addr:  addr,
		nonce: nonce,
	}
	ks = append(ks, firstKey)
	balance, err := ethClient.BalanceAt(context.Background(), addr, nil)
	checkErr(err)
	unit := new(big.Int).Div(balance, big.NewInt(int64(acctNum*100)))

	for i := 0; i < acctNum; i++ {
		k, err := crypto.GenerateKey()
		checkErr(err)
		addr = crypto.PubkeyToAddress(k.PublicKey)
		transferEth(ethClient, first, firstKey.nonce, addr, unit)
		firstKey.nonce++
		tx := genErc20TransferTx(int64(gasPrice), erc20Addr, firstKey, addr, unit)
		err = ethClient.SendTransaction(context.Background(), tx)
		checkErr(err)
		firstKey.nonce++
		nonce, err = ethClient.PendingNonceAt(context.Background(), addr)
		checkErr(err)
		ks = append(ks, &EthKey{
			key:   k,
			addr:  addr,
			nonce: nonce,
		})
	}
	sdk.WaitForGenerateBlock(time.Second*40, 2)
	return ks
}

func transferEth(ethC *ethclient.Client, from *ecdsa.PrivateKey, nonce uint64, to common2.Address, value *big.Int) {
	tx := types.NewTransaction(nonce, to, value, gasLimit, big.NewInt(int64(gasPrice)), []byte{})
	tx, err := types.SignTx(tx, types.HomesteadSigner{}, from)
	checkErr(err)
	err = ethC.SendTransaction(context.Background(), tx)
	checkErr(err)
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
		checkedTxNum := 0
		for checkTx := range checkTxQueue {
			checkedTxNum++
			// 暂时不用
			if !support {
				log.Infof("checkedTxNum: %d", checkedTxNum)
				continue
			}
			for {
				evt, err := sdk.GetSmartContractEvent(checkTx.txHash.ToHexString())
				if evt != nil {
					if evt.State != checkTx.expectState {
						log.Infof("expect state: %d, actual state: %d", checkTx.expectState, evt.State)
						panic(checkTx.txHash.ToHexString())
					} else {
						log.Infof("check tx success,txType: %s, checkedTxNum: %d, txhash: %s", checkTx.txType, checkedTxNum, checkTx.txHash.ToHexString())
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
		res, err = oo.BalanceOf(acct.Address)
		checkErr(err)
		log.Infof("acct balance: %d", res.Uint64())
	}
}

func ontAddrToEthAddr(ontAddr common.Address) common2.Address {
	return common2.BytesToAddress(ontAddr[:])
}

func genErc20TransferTxs(txNum int, contractAddr common2.Address, ethKeys []*EthKey) []*types.Transaction {
	erc20Txs := make([]*types.Transaction, 0)
	rand.Seed(time.Now().Unix())
	l := len(ethKeys)
	var ind, ind2 int
	for i := 0; i < txNum; i++ {
		amt := rand.Int63n(10000)
		ind = i % l
		ind2 = (i + 1) % l
		erc20Tx := genErc20TransferTx(int64(gasPrice), contractAddr, ethKeys[ind], ethKeys[ind2].addr, big.NewInt(amt))
		erc20Txs = append(erc20Txs, erc20Tx)
		ethKeys[ind2].nonce++
	}
	return erc20Txs
}

func genErc20TransferTx(gasPrice int64, contractAddr common2.Address, fromKey *EthKey, toAddr common2.Address, amt *big.Int) *types.Transaction {
	erc20Tx, err := GenEVMTx(fromKey, gasPrice, contractAddr, "transfer", toAddr, amt)
	checkErr(err)
	return erc20Tx
}

func GenEVMTx(from *EthKey, gasPrice int64, contractAddr common2.Address, method string, params ...interface{}) (*types.Transaction, error) {
	chainId := big.NewInt(chainId)
	opts, err := bind.NewKeyedTransactorWithChainID(from.key, chainId)
	checkErr(err)
	opts.GasPrice = big.NewInt(gasPrice)
	opts.Nonce = big.NewInt(int64(from.nonce))
	opts.GasLimit = gasLimit
	parsed, err := abi.JSON(strings.NewReader(WingABI))
	checkErr(err)
	input, err := parsed.Pack(method, params...)
	checkErr(err)
	deployTx := types.NewTransaction(opts.Nonce.Uint64(), contractAddr, opts.Value, opts.GasLimit, opts.GasPrice, input)
	signedTx, err := opts.Signer(opts.From, deployTx)
	checkErr(err)
	return signedTx, err
}

func genOep4Tx(sdk *ontology_go_sdk.OntologySdk, acct *ontology_go_sdk.Account, accts []*ontology_go_sdk.Account, oep4Addr common.Address, txNum int) []*types2.MutableTransaction {
	rand.Seed(time.Now().Unix())
	oep4Txs := make([]*types2.MutableTransaction, 0)

	l := len(accts) + 1
	accts2 := make([]*ontology_go_sdk.Account, l)
	accts2[0] = acct
	copy(accts2[1:], accts)
	var from *ontology_go_sdk.Account
	var toAddr common.Address
	var ind int
	for i := 0; i < txNum; i++ {
		amt := rand.Int63n(1000)
		ind = i % l
		from = accts2[ind]
		ind = (i + 1) % l
		toAddr = accts2[ind].Address
		params := []interface{}{"transfer", []interface{}{from.Address, toAddr, amt}}
		tx, err := sdk.NeoVM.NewNeoVMInvokeTransaction(gasPrice, gasLimit, oep4Addr, params)
		checkErr(err)
		err = sdk.SignToTransaction(tx, from)
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
	if (code == nil || err != nil) && false {
		opts, err := bind.NewKeyedTransactorWithChainID(testPrivateKey, big.NewInt(chainId))
		opts.GasPrice = big.NewInt(int64(gasPrice))
		nonce := getTxNonce(ethClient, ethAddr)
		log.Infof("deploy eth nonce: %d", nonce)
		opts.Nonce = big.NewInt(int64(nonce))
		opts.GasLimit = 8000000
		ethTx, err := NewDeployEvmContract(opts, erc20Code, WingABI)
		checkErr(err)
		err = ethClient.SendTransaction(context.Background(), ethTx)
		checkErr(err)
		txHash := common.Uint256(ethTx.Hash())
		log.Infof("deploy erc20 txHash: %s", txHash.ToHexString())
		sdk.WaitForGenerateBlock(time.Second*40, 1)
		ethAddr = crypto.CreateAddress(testEthAddr, nonce) // 生成新的合约地址
	}
	initContract(sdk, acct, oep4Addr)
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
