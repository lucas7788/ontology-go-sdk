/*
 * Copyright (C) 2018 The ontology Authors
 * This file is part of The ontology library.
 *
 * The ontology is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The ontology is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with The ontology.  If not, see <http://www.gnu.org/licenses/>.
 */
package main

import (
	"fmt"
	"github.com/ontio/ontology-go-sdk"
	common2 "github.com/ontio/ontology-go-sdk/common"
	"github.com/ontio/ontology-go-sdk/examples/define"
	"github.com/ontio/ontology/common"
	"github.com/ontio/ontology/core/utils"
	"io/ioutil"
	"time"
)

var resource_id = []byte("reso_5")

func main() {
	fmt.Println("==========================start============================")
	testUrl := "http://127.0.0.1:20336"
	//mainUrl := "http://dappnode2.ont.io:20336"
	//testUrl = "http://polaris1.ont.io:20336"
	ontSdk := ontology_go_sdk.NewOntologySdk()
	ontSdk.NewRpcClient().SetAddress(testUrl)

	pwd := []byte("123456")

	var seller *ontology_go_sdk.Account
	var buyer *ontology_go_sdk.Account
	var agent *ontology_go_sdk.Account
	var buyer2 *ontology_go_sdk.Account
	var payer *ontology_go_sdk.Account
	var admin *ontology_go_sdk.Account
	wallet, err := ontSdk.OpenWallet("./wallet.dat")
	if false {
		seller, _ = wallet.NewDefaultSettingAccount(pwd)
		buyer, _ = wallet.NewDefaultSettingAccount(pwd)
		buyer2, _ = wallet.NewDefaultSettingAccount(pwd)
		payer, _ = wallet.NewDefaultSettingAccount(pwd)
		admin, _ = wallet.NewDefaultSettingAccount(pwd)
		wallet.Save()
		fmt.Printf("seller:%s, buyer:%s, buyer2:%s, payer:%s,admin:%s\n", seller.Address.ToBase58(),
			buyer.Address.ToBase58(), buyer2.Address.ToBase58(), payer.Address.ToBase58(), admin.Address.ToBase58())
		return
	} else {
		seller, _ = wallet.GetAccountByAddress("Aejfo7ZX5PVpenRj23yChnyH64nf8T1zbu", pwd)
		buyer, _ = wallet.GetAccountByAddress("AHhXa11suUgVLX1ZDFErqBd3gskKqLfa5N", pwd)
		agent, _ = wallet.GetAccountByAddress("ANb3bf1b67WP2ZPh5HQt4rkrmphMJmMCMK", pwd)
		buyer2, _ = wallet.GetAccountByAddress("AQHZ5qq5oS2ZCMwd1q4uX6WGDT4R3Dymm1", pwd)
		payer, _ = wallet.GetAccountByAddress("AQCQ3Krh6qxeWKKRACNehA8kAATHxoQNWJ", pwd)
		admin, _ = wallet.GetAccountByAddress("AYnhakv7kC9R5ppw65JoE2rt6xDzCjCTvD", pwd)
	}

	fmt.Printf("seller:%s, buyer:%s\n", seller.Address.ToBase58(), buyer.Address.ToBase58())

	//273f55776dd52e24c19d7c5deae1c14698dff5df
	wasmfile := "/Users/sss/dev/dockerData/rust_project/ddxf_market/output/ddxf.wasm"

	//0d1a68e43d7c5af11865d743ec87a55a2f9d234d
	//wasmfile = "/Users/sss/dev/dockerData/rust_project/ddxf_market/output/dtoken.wasm"

	code, err := ioutil.ReadFile(wasmfile)
	if err != nil {
		fmt.Printf("error in ReadFile:%s\n", err)
		return
	}

	codeHash := common.ToHexString(code)

	contractAddr := common.AddressFromVmCode(code)

	//contractAddr, _ = common.AddressFromHexString("4caa45728f878f54d458ff860fbd7866f57d81c7")

	//contractAddr, _ = common.AddressFromBase58("APMz8e7KvNQ2YMZgLyoR6VFqvHEL7V1SB4")

	if false {
		c, err := ontSdk.GetSmartContract("bd87a3dcf9eacd9c48f2114b03aee981239a0212")
		if err != nil {
			return
		}
		fmt.Println(c)
		return
	}

	ddxf := NewDDXF(ontSdk, contractAddr, payer)
	fmt.Printf("contractAddr:%s, contractAddr:%s\n", contractAddr.ToBase58(), contractAddr.ToHexString())
	if false {
		ddxf.deploy(seller, codeHash)
		return
	}
	showBalance(ontSdk, seller.Address, buyer.Address)

	//test ddxf contract
	if true {
		tokenHash := make([]byte, 32)
		template := define.TokenTemplate{
			DataIDs:   "",
			TokenHash: string(tokenHash),
		}
		if false {
			param := []interface{}{code, 3, "", "", "", "", ""}
			ddxf.invoke(seller, nil, "migrate", param)
			return
		}
		if false {
			res, err := ddxf.preInvoke("getAdmin", []interface{}{})
			if err != nil {
				fmt.Println(err)
				return
			}
			bs, err := res.ToByteArray()
			if err != nil {
				fmt.Println(err)
				return
			}
			addr, _ := common.AddressParseFromBytes(bs)
			fmt.Println(addr.ToBase58())
			return
		}
		if false {
			dtoken, _ := common.AddressFromHexString("0d1a68e43d7c5af11865d743ec87a55a2f9d234d")
			para := []interface{}{dtoken}
			ddxf.invoke(admin, nil, "setDTokenContract", para)
			res, err := ddxf.preInvoke("getDTokenContract", []interface{}{})
			if err != nil {
				fmt.Println(err)
				return
			}
			bs, _ := res.ToByteArray()
			addr, _ := common.AddressParseFromBytes(bs)
			fmt.Printf("dtoken: %s, addr: %s\n", "0d1a68e43d7c5af11865d743ec87a55a2f9d234d", addr.ToHexString())
			return
		}
		if false {
			param := getPublishParam(seller.Address, tokenHash, template)
			ddxf.invoke(seller, nil, "dtokenSellerPublish", param)
			return
		}

		if false {
			param := []interface{}{resource_id, 1, buyer.Address}
			ddxf.invoke(buyer, nil, "buyDtoken", param)
			showBalance(ontSdk, seller.Address, buyer.Address)
			return
		}

		if false {
			param := []interface{}{resource_id, 1, buyer2.Address, buyer.Address}
			ddxf.invoke(buyer, buyer2, "buyDtokenFromReseller", param)
			showBalance(ontSdk, seller.Address, buyer.Address)
			return
		}
		if false {
			param := []interface{}{resource_id, buyer2.Address, []interface{}{agent.Address}, template.ToBytes(), 1}
			ddxf.invoke(buyer2, nil, "setTokenAgents", param)
			return
		}
		if false {
			param := []interface{}{resource_id, buyer2.Address, agent.Address, template.ToBytes(), 1}
			ddxf.invoke(agent, nil, "useTokenByAgent", param)
			return
		}

		if false {
			param := []interface{}{resource_id, buyer2.Address, []interface{}{agent.Address, admin.Address}, template.ToBytes(), 1}
			ddxf.invoke(buyer2, nil, "setAgents", param)
			return
		}

		if false {
			param := getUseTokenParam(buyer.Address)
			ddxf.invoke(buyer, nil, "useToken", param)
			return
		}

		if false {
			param := []interface{}{resource_id, buyer.Address, []interface{}{agent.Address}, 1}
			bs, _ := utils.BuildWasmContractParam(param)
			fmt.Println(common.ToHexString(bs))
			ddxf.invoke(buyer, nil, "addAgents", param)
			return
		}
		if false {
			param := []interface{}{resource_id, buyer2.Address, template.ToBytes(), []interface{}{agent.Address}, 1}
			ddxf.invoke(buyer2, nil, "addTokenAgents", param)
			return
		}
		if false {
			param := []interface{}{resource_id, template.ToBytes(), buyer2.Address, []interface{}{agent.Address}}
			ddxf.invoke(buyer2, nil, "removeTokenAgents", param)
			return
		}
		if true {
			param := []interface{}{resource_id, buyer2.Address, []interface{}{agent.Address}}
			ddxf.invoke(buyer2, nil, "removeAgents", param)
			return
		}
	}

	//dtoken contract test
	if false {
		tokenHash := make([]byte, 32)
		template := define.TokenTemplate{
			DataIDs:   "",
			TokenHash: string(tokenHash),
		}

		if true {
			//bs,err := common.HexToBytes("4a61b3e02fe54fb1c3c707048a681ae640ea9c03")
			ddxfContract, _ := common.AddressFromHexString("273f55776dd52e24c19d7c5deae1c14698dff5df")
			ddxf.invoke(admin, nil, "setDdxfContract", []interface{}{ddxfContract})
			res, err := ddxf.preInvoke("getDdxfContract", []interface{}{})
			if err != nil {
				return
			}
			bs, err := res.ToByteArray()
			if err != nil {
				return
			}
			ddxfContractAddr, err := common.AddressParseFromBytes(bs)
			fmt.Printf("raw ddxfContract: %s,ddxfContractAddr: %s\n",
				"273f55776dd52e24c19d7c5deae1c14698dff5df", ddxfContractAddr.ToHexString())
			return
		}
		//templates := []define.TokenTemplate{template}
		if false {
			//ddxf.invoke(seller, "generateDToken", []interface{}{seller.Address, resource_id, serializeTokenTemplate(templates), 1})
			res, _ := ddxf.preInvoke("getCountAndAgent", []interface{}{resource_id, buyer.Address, template.ToBytes()})
			bs, _ := res.ToByteArray()
			caa := &define.CountAndAgent{}
			caa.FromBytes(bs)
			fmt.Println("caa:", caa)
			return
		}

		if true {
			ddxf.invoke(seller, nil, "useToken", []interface{}{seller.Address, resource_id, template.ToBytes(), 1})
		}
		return
	}
}

func showBalance(ontSdk *ontology_go_sdk.OntologySdk, seller common.Address, buyer common.Address) {
	seller_ba, _ := ontSdk.Native.Ong.BalanceOf(seller)
	buyer_ba, _ := ontSdk.Native.Ong.BalanceOf(buyer)
	fmt.Printf("seller_ba:%d,buyer_ba:%d\n", seller_ba, buyer_ba)
}

func getUseTokenParam(buyer common.Address) []interface{} {
	tokenHash := make([]byte, 32)
	template := define.TokenTemplate{
		DataIDs:   "",
		TokenHash: string(tokenHash),
	}
	return []interface{}{resource_id, buyer, template.ToBytes(), 1}
}

func serializeTokenTemplate(templates []define.TokenTemplate) []byte {
	sink := common.NewZeroCopySink(nil)
	sink.WriteUint32(uint32(len(templates)))
	for _, i := range templates {
		i.Serialize(sink)
	}
	return sink.Bytes()
}

func getPublishParam(seller common.Address, tokenHash []byte, template define.TokenTemplate) []interface{} {
	tokenResourceType := make(map[define.TokenTemplate]byte)
	tokenResourceType[template] = byte(0)
	tokenEndpoint := make(map[define.TokenTemplate]string)
	tokenEndpoint[template] = "endpoint2"
	ddo := define.ResourceDDO{
		ResourceType:      byte(1),
		TokenResourceType: tokenResourceType,    // RT for tokens
		Manager:           seller,               // data owner id
		Endpoint:          "endpoint",           // data service provider uri
		TokenEndpoint:     tokenEndpoint,        // endpoint for tokens
		DescHash:          "",                   // required if len(Templates) > 1
		DTC:               common.ADDRESS_EMPTY, // can be empty
		MP:                common.ADDRESS_EMPTY, // can be empty
		Split:             common.ADDRESS_EMPTY,
	}

	item := define.DTokenItem{
		Fee: define.Fee{
			ContractAddr: common.ADDRESS_EMPTY,
			ContractType: byte(1),
			Count:        100,
		},
		ExpiredDate: uint64(time.Now().Unix()) + uint64(36000),
		Stocks:      1,
		Templates:   []define.TokenTemplate{template},
	}
	return []interface{}{resource_id, ddo.ToBytes(), item.ToBytes()}
}

type DDXF struct {
	sdk             *ontology_go_sdk.OntologySdk
	gasLimit        uint64
	gasPrice        uint64
	contractAddress common.Address
	timeoutSec      time.Duration
	payer           *ontology_go_sdk.Account
}

func NewDDXF(sdk *ontology_go_sdk.OntologySdk, contractAddress common.Address, payer *ontology_go_sdk.Account) *DDXF {
	return &DDXF{
		sdk:             sdk,
		gasLimit:        200000000,
		gasPrice:        0,
		contractAddress: contractAddress,
		timeoutSec:      30 * time.Second,
		payer:           payer,
	}
}

func (this *DDXF) deploy(signer *ontology_go_sdk.Account, codeHash string) error {

	txHash, err := this.sdk.WasmVM.DeployWasmVMSmartContract(
		this.gasPrice,
		this.gasLimit,
		signer,
		codeHash,
		"ddxf wasm",
		"1.0",
		"author",
		"email",
		"desc",
	)

	if err != nil {
		fmt.Printf("error in DeployWasmVMSmartContract:%s\n", err)
		return err
	}
	_, err = this.sdk.WaitForGenerateBlock(this.timeoutSec)
	if err != nil {
		fmt.Printf("error in WaitForGenerateBlock:%s\n", err)

		return err
	}
	fmt.Printf("the deploy contract txhash is %s\n", txHash.ToHexString())
	return nil
}

func (this *DDXF) preInvoke(method string, param []interface{}) (*common2.ResultItem, error) {
	res, err := this.sdk.WasmVM.PreExecInvokeWasmVMContract(this.contractAddress, method, param)
	if err != nil {
		fmt.Println("InvokeWasmVMSmartContract error ", err)
		return nil, err
	}
	fmt.Printf("state:%d\n", res.State)
	return res.Result, nil
}

func (this *DDXF) invoke(signer1, signer2 *ontology_go_sdk.Account, method string, param []interface{}) error {
	if signer2 == nil {
		signer2 = this.payer
	}
	txhash, err := this.sdk.WasmVM.InvokeWasmVMSmartContract(this.gasPrice, this.gasLimit, signer1, signer2, this.contractAddress, method, param)
	if err != nil {
		fmt.Println("InvokeWasmVMSmartContract error ", err)
		return err
	}

	timeoutSec := 30 * time.Second
	_, err = this.sdk.WaitForGenerateBlock(timeoutSec)
	if err != nil {
		fmt.Println("WaitForGenerateBlock error ", err)
		return err
	}
	fmt.Printf("method:%s, txHash:%s\n", method, txhash.ToHexString())
	event, err := this.sdk.GetSmartContractEvent(txhash.ToHexString())
	if err != nil {
		fmt.Println("GetSmartContractEvent error ", err)
		return err
	}
	if event != nil {
		for _, notify := range event.Notify {
			fmt.Printf("%+v\n", notify)
		}
	}
	return nil
}
