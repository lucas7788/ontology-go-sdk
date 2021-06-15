package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum"
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
var transferAmt, txNums, acctNum int
var ongDecimal = 1000000000

func main() {

	chainId = 12345
	gasPrice = 500
	gasLimit = 210000
	txNums = 100000   // 压测交易数量
	acctNum = 2       // 随机生成的账户数量
	transferAmt = 100 // oep4 和 erc20 转账的数量

	sdk := ontology_go_sdk.NewOntologySdk()
	testNet := "http://172.168.3.73:30336"
	//testNet = "http://127.0.0.1:20336"
	//testNet = "http://192.168.0.189:20336"
	testNet = "http://172.168.3.73:20336"

	sdk.NewRpcClient().SetAddress(testNet)

	if false {
		txs, err := sdk.GetMemPoolTxHashList()
		checkErr(err)
		a := "8b5ec95b523a0659f711fa6f857644f61850e1daa789ddc001c3ebec2ba16e63"
		for _, hash := range txs {
			//fmt.Println(hash.ToHexString())
			if hash.ToHexString() == a {
				panic(hash.ToHexString())
			}
		}
		return
	}

	testNet = "http://172.168.3.73:30339"
	//testNet = "http://127.0.0.1:20339"
	//testNet = "http://192.168.0.189:20339"
	testNet = "http://172.168.3.73:20339"

	ethClient, err := ethclient.Dial(testNet)
	checkErr(err)

	wallet, err := sdk.OpenWallet("wallet.dat")
	checkErr(err)
	acct, err := wallet.GetDefaultAccount([]byte("server"))
	checkErr(err)

	testPrivateKeyStr := "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
	testPrivateKey, err = crypto.HexToECDSA(testPrivateKeyStr)
	checkErr(err)
	testEthAddr := crypto.PubkeyToAddress(testPrivateKey.PublicKey)
	testEthAddrOnt := common.Address(testEthAddr)
	log.Infof("testEthAddrOnt: %s", testEthAddrOnt.ToBase58())
	transferOng(sdk, acct, common.Address(testEthAddr), uint64(txNums*ongDecimal*5/100/acctNum))
	sdk.WaitForGenerateBlock(time.Second*40, 1)

	oep4Addr, erc20Addr := deployContract(sdk, ethClient, acct, testPrivateKey)
	log.Infof("oep4Addr: %s, erc20Addr: %s", oep4Addr.ToHexString(), erc20Addr.String())

	if false {
		bal := erc20BalanceOf(erc20Addr, ethClient, testEthAddr)
		fmt.Println(bal)
		return
	}
	exit := make(chan bool, 0)
	checkTxQueue := make(chan CheckTx, 10000)
	oep4Token := oep4.NewOep4(oep4Addr, sdk)
	startCheckTxTask(sdk, checkTxQueue, true, exit, oep4Token, ethClient)
	//txQueue := make(chan string, 10000)
	//startGetMempoolTxTask(sdk, txQueue, true, exit)

	accts := genAccts(sdk, wallet, acctNum, acct, oep4Addr, txNums)
	ethKeys := genEthPrivateKey(acctNum, testPrivateKey, ethClient, erc20Addr, sdk, acct, txNums)

	// 正常交易压力测试
	if true {
		testStress(sdk, acct, accts, oep4Addr, txNums, ethClient, ethKeys, erc20Addr, checkTxQueue)
	}

	// 相同的txNonce交易  交易手续费大的应该成功
	if false {
		testNonce(ethClient, erc20Addr, ethKeys, checkTxQueue, txNums)
	}
	close(checkTxQueue)
	<-exit
	<-exit
	log.Info("*************** test end ******************")
}

func testStress(sdk *ontology_go_sdk.OntologySdk, acct *ontology_go_sdk.Account, accts []*ontology_go_sdk.Account,
	oep4Addr common.Address, txNum int, ethClient *ethclient.Client, ethKeys []*EthKey, erc20Addr common2.Address,
	checkTxQueue chan CheckTx) {
	oep4Txs := genOep4Tx(sdk, acct, accts, oep4Addr, txNum)

	erc20Txs := genErc20TransferTxs(txNum, erc20Addr, ethKeys)

	var hash common.Uint256
	for i := 0; i < txNum; i++ {
		hash = oep4Txs[i].Hash()
		log.Infof("testStress i: %d start, txHash: %s", i, hash.ToHexString())
		txHash, err := sdk.SendTransaction(oep4Txs[i])
		log.Infof("testStress i: %d end", i)
		checkErr(err)
		checkTxQueue <- NewCheckTx("oep4", txHash, 1, 0, oep4Txs[i].Payer, oep4Addr)
		hash = common.Uint256(erc20Txs[i].tx.Hash())
		log.Infof("erc20 , i: %d,nonce: %d, txHash: %s start", i, erc20Txs[i].tx.Nonce(), hash.ToHexString())
		err = ethClient.SendTransaction(context.Background(), erc20Txs[i].tx)
		log.Infof("erc20 , i: %d, end", i)
		checkErr(err)
		checkTxQueue <- NewCheckTx("erc20", common.Uint256(erc20Txs[i].tx.Hash()), 1, erc20Txs[i].tx.Nonce(),
			common.Address(erc20Txs[i].payer), common.Address(erc20Addr))
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
		erc20Tx := genErc20TransferTx(int64(gasPrice), erc20Addr, from, toAddr, big.NewInt(int64(transferAmt)))
		erc20Tx2 := genErc20TransferTx(int64(gasPrice+10), erc20Addr, from, toAddr, big.NewInt(int64(transferAmt+1)))
		thash := common.Uint256(erc20Tx.Hash())
		log.Infof("erc20Tx:", thash.ToHexString())
		err := ethClient.SendTransaction(context.Background(), erc20Tx)
		thash = common.Uint256(erc20Tx2.Hash())
		log.Infof("erc20Tx2:", thash.ToHexString())
		checkErr(err)
		checkTxQueue <- NewCheckTx("erc20", common.Uint256(erc20Tx.Hash()), 0, from.nonce,
			common.Address(crypto.PubkeyToAddress(from.key.PublicKey)), common.Address(erc20Addr))
		//err = ethClient.SendTransaction(context.Background(), erc20Tx2)
		//checkErr(err)
		//checkTxQueue <- NewCheckTx("erc20", common.Uint256(erc20Tx2.Hash()), 1)
		from.nonce++
	}
}

func genAccts(sdk *ontology_go_sdk.OntologySdk, wallet *ontology_go_sdk.Wallet, acctNum int, acct *ontology_go_sdk.Account,
	oep4Addr common.Address, txNums int) []*ontology_go_sdk.Account {
	accts := make([]*ontology_go_sdk.Account, 0)
	unit := uint64(txNums * ongDecimal * 2 * 5 / 100)
	unit = unit / uint64(acctNum)
	token := oep4.NewOep4(oep4Addr, sdk)
	oBalance, err := token.BalanceOf(acct.Address)
	checkErr(err)
	unit2 := new(big.Int).Div(oBalance, big.NewInt(int64(acctNum*100)))
	var acct2 *ontology_go_sdk.Account
	for i := 0; i < acctNum; i++ {
		acct2, err = wallet.NewDefaultSettingAccount([]byte("111111"))
		checkErr(err)
		log.Infof("genAccts uint: %d", unit)
		transferOng(sdk, acct, acct2.Address, unit)
		if unit2.Uint64() > 0 {
			_, err = token.Transfer(acct, acct2.Address, unit2, acct, gasPrice, gasLimit)
			checkErr(err)
		}
		accts = append(accts, acct2)
	}
	sdk.WaitForGenerateBlock(time.Second*40, 2)
	for _, a := range accts {
		ba, err := sdk.Native.Ong.BalanceOf(a.Address)
		checkErr(err)
		log.Infof("ba: %d", ba)
	}
	return accts
}

func transferOng(sdk *ontology_go_sdk.OntologySdk, from *ontology_go_sdk.Account, to common.Address, amt uint64) {
	_, err := sdk.Native.Ong.Transfer(gasPrice, gasLimit, from, from, to, amt)
	checkErr(err)
}

type EthKey struct {
	key   *ecdsa.PrivateKey
	addr  common2.Address
	nonce uint64
}

func genEthPrivateKey(acctNum int, first *ecdsa.PrivateKey, ethClient *ethclient.Client, erc20Addr common2.Address,
	sdk *ontology_go_sdk.OntologySdk, acct *ontology_go_sdk.Account, txNums int) []*EthKey {
	ks := make([]*EthKey, 0)
	addr := crypto.PubkeyToAddress(first.PublicKey)
	nonce, err := ethClient.PendingNonceAt(context.Background(), addr)
	checkErr(err)
	firstKey := &EthKey{
		key:   testPrivateKey,
		addr:  addr,
		nonce: nonce,
	}

	unit := txNums * ongDecimal * 2 * 5 / 100
	unit = unit / acctNum

	log.Infof("genEthPrivateKey, unit: %d", unit)
	for i := 0; i < acctNum; i++ {
		k, err := crypto.GenerateKey()
		checkErr(err)
		addr = crypto.PubkeyToAddress(k.PublicKey)
		transferOng(sdk, acct, common.Address(addr), uint64(unit))
		tx := genErc20TransferTx(int64(gasPrice), erc20Addr, firstKey, addr, big.NewInt(int64(unit)))
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
	for _, a := range ks {
		ba, err := sdk.Native.Ong.BalanceOf(common.Address(a.addr))
		checkErr(err)
		log.Infof("****ba: %d", ba)
	}
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
	txType       string
	txHash       common.Uint256
	expectState  byte
	nonce        uint64
	payer        common.Address
	contractAddr common.Address
}

func NewCheckTx(txType string, txHash common.Uint256, expectState byte, nonce uint64, payer, contractAddr common.Address) CheckTx {
	return CheckTx{
		txType:       txType,
		txHash:       txHash,
		expectState:  expectState,
		nonce:        nonce,
		payer:        payer,
		contractAddr: contractAddr,
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

func startCheckTxTask(sdk *ontology_go_sdk.OntologySdk, checkTxQueue chan CheckTx, support bool, exit chan bool,
	oep4Token *oep4.Oep4, ethClient *ethclient.Client) {
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
						//log.Infof("check tx success,txType: %s, checkedTxNum: %d, txhash: %s", checkTx.txType, checkedTxNum, checkTx.txHash.ToHexString())
						break
					}
				} else {
					if err != nil {
						log.Errorf("txType: %s, txhash: %s, err: %s", checkTx.txType, checkTx.txHash.ToHexString(), err)
					}
					balance, err := sdk.Native.Ong.BalanceOf(checkTx.payer)
					checkErr(err)
					var tokenBalance *big.Int
					if checkTx.txType == "oep4" {
						tokenBalance, err = oep4Token.BalanceOf(checkTx.payer)
						checkErr(err)
					} else if checkTx.txType == "erc20" {
						tokenBalance = erc20BalanceOf(common2.Address(checkTx.contractAddr), ethClient, common2.Address(checkTx.payer))
					}
					log.Infof("wait tx, txType: %s, ong balance: %d, token balance: %s, txhash: %s", checkTx.txType, balance, tokenBalance.String(), checkTx.txHash.ToHexString())
					time.Sleep(3 * time.Second)
					continue
				}
			}
		}
		exit <- true
	}()
}

// get tx
func startGetMempoolTxTask(sdk *ontology_go_sdk.OntologySdk, txHashQueue chan string, support bool, exit chan bool) {
	go func() {
		checkedTxNum := 0
		for hash := range txHashQueue {
			checkedTxNum++
			// 暂时不用
			if !support {
				log.Infof("checkedTxNum: %d", checkedTxNum)
				continue
			}
			count, err := sdk.GetMemPoolTxCount()
			checkErr(err)
			txState, err := sdk.GetMemPoolTxState(hash)
			checkErr(err)
			txStateBs, err := json.Marshal(txState)
			checkErr(err)
			log.Infof("MemPoolTxCount: %d, txState: %s", count, string(txStateBs))
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

type Erc20TransferTx struct {
	tx    *types.Transaction
	payer common2.Address
}

func genErc20TransferTxs(txNum int, contractAddr common2.Address, ethKeys []*EthKey) []*Erc20TransferTx {
	erc20Txs := make([]*Erc20TransferTx, 0)
	rand.Seed(time.Now().Unix())
	l := len(ethKeys)
	var ind, ind2 int
	var amt int64
	for i := 0; i < txNum; i++ {
		amt = 1000
		ind = i % l
		ind2 = (i + 1) % l
		erc20Tx := genErc20TransferTx(int64(gasPrice), contractAddr, ethKeys[ind], ethKeys[ind2].addr, big.NewInt(amt))
		tx := &Erc20TransferTx{
			tx:    erc20Tx,
			payer: crypto.PubkeyToAddress(ethKeys[ind].key.PublicKey),
		}
		erc20Txs = append(erc20Txs, tx)
		ethKeys[ind].nonce++
	}
	return erc20Txs
}

func genErc20TransferTx(gasPrice int64, contractAddr common2.Address, fromKey *EthKey, toAddr common2.Address, amt *big.Int) *types.Transaction {
	erc20Tx, err := GenEVMTx(fromKey, gasPrice, contractAddr, "transfer", toAddr, amt)
	checkErr(err)
	return erc20Tx
}

func erc20BalanceOf(contractAddr common2.Address, ethClient *ethclient.Client, addr common2.Address) *big.Int {
	//erc20, err := eth.NewErc20(contractAddr, ethClient)
	//checkErr(err)
	//balance, err := erc20.BalanceOf(&bind.CallOpts{Pending: false}, addr)
	if true {
		return big.NewInt(0)
	}
	parsed, err := abi.JSON(strings.NewReader(WingABI))
	checkErr(err)
	input, err := parsed.Pack("balanceOf", addr)
	opts := &bind.CallOpts{Pending: false}
	msg := ethereum.CallMsg{From: opts.From, To: &contractAddr, Data: input}
	output, err := ethClient.CallContract(context.Background(), msg, opts.BlockNumber)
	checkErr(err)
	res, err := parsed.Unpack("balanceOf", output)
	checkErr(err)
	d := res[0].(*big.Int)
	return d
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
		ind = i % l
		from = accts2[ind]
		ind = (i + 1) % l
		toAddr = accts2[ind].Address
		params := []interface{}{"transfer", []interface{}{from.Address, toAddr, transferAmt}}
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
	oep4Code := loadContract("test-contract/WingToken.avm")
	erc20Code := loadContract("test-contract/wing_eth.evm")

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
	mutable, err := utils.NewDeployCodeTransaction(gasPrice, gasLimit*100, code, payload.NEOVM_TYPE, "name", "version",
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
