package main

import (
	"encoding/hex"
	"fmt"
	"github.com/ontio/ontology-go-sdk"
	"github.com/ontio/ontology/common"
	"io/ioutil"
	"time"
)

var (
	defGasPrice = uint64(0)
)

func main() {
	sdk := ontology_go_sdk.NewOntologySdk()
	sdk.NewRpcClient().SetAddress("http://polaris1.ont.io:20336")
	sdk.NewRpcClient().SetAddress("http://127.0.0.1:20336")
	//sdk.NewRpcClient().SetAddress("http://172.168.3.174:20336")

	pwd := []byte("111111")

	wallet, _ := sdk.OpenWallet("./wallet3.dat")
	acc1, err := wallet.GetAccountByAddress("AbtTQJYKfQxq4UdygDsbLVjE8uRrJ2H3tP", pwd)
	if err != nil {
		fmt.Printf("OpenWallet error: %s", err)
		return
	}
	neofile := "/Users/sss/dev/localgit/ontology-python-compiler/ontology_test/example/ChainOp/vote.avm"
	code, err := ioutil.ReadFile(neofile)
	if err != nil {
		fmt.Printf("error in ReadFile:%s\n", err)
		return
	}

	codeStr := hex.EncodeToString(code)
	contractAddress := common.AddressFromVmCode(code)
	fmt.Println("contract contractAddress: ", contractAddress.ToHexString())

	if false {
		hash, err := sdk.NeoVM.DeployNeoVMSmartContract(defGasPrice, 2060000000, acc1, true, codeStr,
			"", "", "", "", "")
		if err != nil {
			fmt.Println("err:", err)
			return
		}
		fmt.Println("hash:", hash.ToHexString())
		time.Sleep(6 * time.Second)
		eve, _ := sdk.GetSmartContractEvent(hash.ToHexString())
		fmt.Println("eve:", eve)
		return
	}

	if false {
		txHash, err := sdk.NeoVM.InvokeNeoVMContract(defGasPrice, 20000000,
			acc1, acc1, contractAddress, []interface{}{"createTopic", []interface{}{
				acc1.Address, "test_title2", "test_detail2", time.Now().Unix(),
				time.Now().Unix() + 100000, []interface{}{[]interface{}{acc1.Address, 10000}}}})
		if err != nil {
			fmt.Println("createTopic error: ", err)
			return
		}
		time.Sleep(6 * time.Second)
		evt, err := sdk.GetSmartContractEvent(txHash.ToHexString())
		if err != nil {
			fmt.Println("createTopic error: ", err)
			return
		}
		for _,notify := range evt.Notify {
			fmt.Println("createTopic evt: ", *notify)
		}
		fmt.Println("createTopic evt: ", evt.Notify)
		return
	}
	//neo
	//a088ae3b508794e666ab649d890213e66e0c3a2e
	//contractAddress, _ = common.AddressFromHexString("a088ae3b508794e666ab649d890213e66e0c3a2e")
	if false {
		res, err := sdk.NeoVM.PreExecInvokeNeoVMContract(contractAddress,
			[]interface{}{"listTopics", []interface{}{}})
		if err != nil {
			fmt.Println("listTopics error: ", err)
			return
		}
		arr, err := res.Result.ToArray()
		if err != nil {
			fmt.Println("listTopics ToArray error: ", err)
			return
		}
		arr1, _ := arr[0].ToByteArray()
		fmt.Println("res:", hex.EncodeToString(arr1))
		return
	}

	if true {
		//local bbab28299c699e57db9113d17be63b1f70da58d100100538c35065e69bcda876
		//test net  17b6cda74eeb9f7f1d3cf469bf4111ab58e181c601bd84d2421d91edeb2612ba
		//topic_hash ,_ := common.Uint256FromHexString("56ff666d80219e1c2c81e95644a5911748096d37210873fa97523258906387a4")
		topic_hash, _ := hex.DecodeString("56ff666d80219e1c2c81e95644a5911748096d37210873fa97523258906387a4")
		res, err := sdk.NeoVM.PreExecInvokeNeoVMContract(contractAddress,
			[]interface{}{"getTopicInfo", []interface{}{topic_hash}})
		if err != nil {
			fmt.Println("listTopics error: ", err)
			return
		}
		arr, err := res.Result.ToArray()
		if err != nil {
			fmt.Println("listTopics ToArray error: ", err)
			return
		}
		arr1, _ := arr[0].ToByteArray()
		fmt.Println("res:", hex.EncodeToString(arr1))
		return
	}

	if true {
		res, err := sdk.Native.PreExecInvokeNativeContract(ontology_go_sdk.GOVERNANCE_CONTRACT_ADDRESS,0,"getPeerPool",[]interface{}{})
		if err != nil {
			fmt.Println("err: ", err)
			return
		}
		bs, _ := res.Result.ToByteArray()
		fmt.Println("res:", hex.EncodeToString(bs))
	}
}
