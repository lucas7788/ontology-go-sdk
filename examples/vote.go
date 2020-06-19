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
	defGasPrice = uint64(500)
)

func main() {
	sdk := ontology_go_sdk.NewOntologySdk()
	sdk.NewRpcClient().SetAddress("http://polaris1.ont.io:20336")
	//sdk.NewRpcClient().SetAddress("http://127.0.0.1:20336")
	//sdk.NewRpcClient().SetAddress("http://172.168.3.174:20336")

	pwd := []byte("111111")

	wallet, _ := sdk.OpenWallet("./wallet3.dat")
	acc1, err := wallet.GetAccountByAddress("AbtTQJYKfQxq4UdygDsbLVjE8uRrJ2H3tP", pwd)
	if err != nil {
		fmt.Printf("OpenWallet error: %s", err)
		return
	}
	wasmfile := "/Users/sss/dev/dockerData/rust_project/vote/output/vote.wasm"
	code, err := ioutil.ReadFile(wasmfile)
	if err != nil {
		fmt.Printf("error in ReadFile:%s\n", err)
		return
	}

	codeStr := hex.EncodeToString(code)
	contractAddress := common.AddressFromVmCode(code)
	fmt.Println("contract contractAddress: ", contractAddress.ToHexString())

	if false {
		hash, err := sdk.WasmVM.DeployWasmVMSmartContract(defGasPrice, 2060000000, acc1, codeStr,
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
		res, err := sdk.WasmVM.PreExecInvokeWasmVMContract(contractAddress, "listTopics", []interface{}{})
		if err != nil {
			fmt.Println("listTopics error: ", err)
			return
		}
		arr, err := res.Result.ToByteArray()
		if err != nil {
			fmt.Println("listTopics ToArray error: ", err)
			return
		}
		//arr1,_ := arr[0].ToByteArray()
		source := common.NewZeroCopySource(arr)
		l,_,_,_ := source.NextVarUint()
		for i:=0;i<int(l);i++ {
			h,_ := source.NextHash()
			fmt.Println("h:", h.ToHexString())
		}
		fmt.Println("res:", hex.EncodeToString(arr))
		return
	}
	if false {
		res, err := sdk.WasmVM.PreExecInvokeWasmVMContract(contractAddress, "listAdmins", []interface{}{""})
		if err != nil {
			fmt.Println("listTopics error: ", err)
			return
		}
		arr, err := res.Result.ToByteArray()
		if err != nil {
			fmt.Println("listTopics ToArray error: ", err)
			return
		}
		//arr1,_ := arr[0].ToByteArray()
		source := common.NewZeroCopySource(arr)
		l,_,_,_ := source.NextVarUint()
		for i:=0;i<int(l);i++ {
			h,_ := source.NextAddress()
			fmt.Println("h:", h.ToBase58())
		}
		fmt.Println("res:", hex.EncodeToString(arr))
		return
	}

	if false {
		//56ff666d80219e1c2c81e95644a5911748096d37210873fa97523258906387a4
		bs, _ := hex.DecodeString("ba1226ebed911d42d284bd01c681e158ab1141bf69f43c1d7f9feb4ea7cdb617")
		topic_hash, _ := common.Uint256ParseFromBytes(bs)
		topic_hash, _ = common.Uint256FromHexString("a480262f34cb7d54b1cb2d34b3b416029e4b97bfd4a6424b1e10ce62f4a3dce2")
		res, err := sdk.WasmVM.PreExecInvokeWasmVMContract(contractAddress,
			"getTopicInfo", []interface{}{topic_hash})
		if err != nil {
			fmt.Println("listTopics error: ", err)
			return
		}
		arr, err := res.Result.ToByteArray()
		if err != nil {
			fmt.Println("listTopics ToArray error: ", err)
			return
		}
		//arr1,_ := arr[0].ToByteArray()
		source := common.NewZeroCopySource(arr)
		l,_,_,_ := source.NextVarUint()
		for i:=0;i<int(l);i++ {
			h,_ := source.NextAddress()
			fmt.Println("h:", h.ToBase58())
		}
		fmt.Println("res:", hex.EncodeToString(arr))
		return
	}

	if false {
		//56ff666d80219e1c2c81e95644a5911748096d37210873fa97523258906387a4
		bs, _ := hex.DecodeString("56ff666d80219e1c2c81e95644a5911748096d37210873fa97523258906387a4")
		topic_hash, _ := common.Uint256ParseFromBytes(bs)
		topic_hash, _ = common.Uint256FromHexString("0452a1657821735f40e5052869db07049376b174f823eae9b6a445059a430c54")
		res, err := sdk.WasmVM.PreExecInvokeWasmVMContract(contractAddress,
			"getVotedAddress", []interface{}{topic_hash})
		if err != nil {
			fmt.Println("listTopics error: ", err)
			return
		}
		arr, err := res.Result.ToByteArray()
		if err != nil {
			fmt.Println("listTopics ToArray error: ", err)
			return
		}
		//arr1,_ := arr[0].ToByteArray()
		source := common.NewZeroCopySource(arr)
		l,_,_,_ := source.NextVarUint()
		for i:=0;i<int(l);i++ {
			h,_ := source.NextAddress()
			fmt.Println("h:", h.ToBase58())
		}
		fmt.Println("res:", hex.EncodeToString(arr))
		return
	}

	if false {
		//56ff666d80219e1c2c81e95644a5911748096d37210873fa97523258906387a4
		bs, _ := hex.DecodeString("56ff666d80219e1c2c81e95644a5911748096d37210873fa97523258906387a4")
		topic_hash, _ := common.Uint256ParseFromBytes(bs)
		topic_hash, _ = common.Uint256FromHexString("6744d492a15537185ff5b3eb7a7503b28ea9948c0ada2d6f817ea6fe6e38fbfb")
		res, err := sdk.WasmVM.PreExecInvokeWasmVMContract(contractAddress,
			"getTopic", []interface{}{topic_hash})
		if err != nil {
			fmt.Println("listTopics error: ", err)
			return
		}
		arr, err := res.Result.ToByteArray()
		if err != nil {
			fmt.Println("listTopics ToArray error: ", err)
			return
		}
		//arr1,_ := arr[0].ToByteArray()
		source := common.NewZeroCopySource(arr)
		l,_,_,_ := source.NextVarUint()
		for i:=0;i<int(l);i++ {
			h,_ := source.NextAddress()
			fmt.Println("h:", h.ToBase58())
		}
		fmt.Println("res:", hex.EncodeToString(arr))
		return
	}

	if false {
		//56ff666d80219e1c2c81e95644a5911748096d37210873fa97523258906387a4
		bs, _ := hex.DecodeString("ba1226ebed911d42d284bd01c681e158ab1141bf69f43c1d7f9feb4ea7cdb617")
		topic_hash, _ := common.Uint256ParseFromBytes(bs)
		topic_hash, _ = common.Uint256FromHexString("911d643606a8a541fdae3f700ef79cbf80052217d43c564cd376749d3d2f41d4")
		voter,_ := common.AddressFromBase58("AQA78PhrfE2kvA5HxJvXvKytTmpqgrgBts")
		res, err := sdk.WasmVM.PreExecInvokeWasmVMContract(contractAddress,
			"getVotedInfo", []interface{}{topic_hash, voter})
		if err != nil {
			fmt.Println("listTopics error: ", err)
			return
		}
		arr, err := res.Result.ToByteArray()
		if err != nil {
			fmt.Println("listTopics ToArray error: ", err)
			return
		}
		//arr1,_ := arr[0].ToByteArray()
		source := common.NewZeroCopySource(arr)
		l,_,_,_ := source.NextVarUint()
		for i:=0;i<int(l);i++ {
			h,_ := source.NextAddress()
			fmt.Println("h:", h.ToBase58())
		}
		fmt.Println("res:", hex.EncodeToString(arr))
		return
	}

	if true {
		sdk.WasmVM.InvokeWasmVMSmartContract(defGasPrice,20000000,
			acc1,acc1,contractAddress,"create_topic",
			[]interface{}{})
	}
}
