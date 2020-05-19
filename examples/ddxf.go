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

var resource_id = []byte("reso_1")

func main() {
	fmt.Println("==========================start============================")
	testUrl := "http://127.0.0.1:20336"
	//mainUrl := "http://dappnode2.ont.io:20336"
	testUrl = "http://polaris1.ont.io:20336"
	ontSdk := ontology_go_sdk.NewOntologySdk()
	ontSdk.NewRpcClient().SetAddress(testUrl)

	pwd := []byte("123456")

	var seller *ontology_go_sdk.Account
	var buyer *ontology_go_sdk.Account
	var agent *ontology_go_sdk.Account
	wallet, err := ontSdk.OpenWallet("./wallet.dat")
	if false {
		seller, _ = wallet.NewDefaultSettingAccount(pwd)
		buyer, _ = wallet.NewDefaultSettingAccount(pwd)
		wallet.Save()
		fmt.Printf("seller:%s, buyer:%s\n", seller.Address.ToBase58(), buyer.Address.ToBase58())
		return
	} else {
		seller, _ = wallet.GetAccountByAddress("Aejfo7ZX5PVpenRj23yChnyH64nf8T1zbu", pwd)
		buyer, _ = wallet.GetAccountByAddress("AHhXa11suUgVLX1ZDFErqBd3gskKqLfa5N", pwd)
		agent, _ = wallet.GetAccountByAddress("ANb3bf1b67WP2ZPh5HQt4rkrmphMJmMCMK", pwd)
	}

	fmt.Printf("seller:%s, buyer:%s\n", seller.Address.ToBase58(), buyer.Address.ToBase58())

	wasmfile := "/Users/sss/dev/dockerData/rust_project/ddxf_market/output/ddxf.wasm"

	//wasmfile = "/Users/sss/dev/dockerData/rust_project/ddxf_market/output/dtoken.wasm"

	code, err := ioutil.ReadFile(wasmfile)
	if err != nil {
		fmt.Printf("error in ReadFile:%s\n", err)
		return
	}

	codeHash := common.ToHexString(code)

	contractAddr := common.AddressFromVmCode(code)

	ddxf := NewDDXF(ontSdk, contractAddr)
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
			param := getPublishParam(seller.Address, tokenHash, template)
			ddxf.invoke(seller, "dtokenSellerPublish", param)
			return
		}

		if false {
			param := getBuyTokenParam(buyer.Address)
			ddxf.invoke(buyer, "buyDtoken", param)
			showBalance(ontSdk, seller.Address, buyer.Address)
			return
		}

		if false {
			param := getUseTokenParam(buyer.Address)
			ddxf.invoke(buyer, "useToken", param)
			return
		}
		if true {
			res, err := ddxf.preInvoke("getCountAndAgent",[]interface{}{buyer.Address,resource_id,template.ToBytes()})
			if err != nil {
				fmt.Println("error:", err)
				return
			}
			res.ToByteArray()
		}

		if false {
			param := []interface{}{resource_id, buyer.Address, []interface{}{agent.Address}, 1}
			bs, _ := utils.BuildWasmContractParam(param)
			fmt.Println(common.ToHexString(bs))
			ddxf.invoke(buyer, "addAgents", param)
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
			ddxf.invoke(seller, "useToken", []interface{}{seller.Address, resource_id, template.ToBytes(), 1})
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
func getBuyTokenParam(buyer common.Address) []interface{} {
	return []interface{}{resource_id, 1, buyer}
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
		ExpiredDate: uint64(time.Now().Unix()) + uint64(1000),
		Stocks:      100,
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
}

func NewDDXF(sdk *ontology_go_sdk.OntologySdk, contractAddress common.Address) *DDXF {
	return &DDXF{
		sdk:             sdk,
		gasLimit:        200000000,
		gasPrice:        500,
		contractAddress: contractAddress,
		timeoutSec:      30 * time.Second,
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

func (this *DDXF) invoke(signer *ontology_go_sdk.Account, method string, param []interface{}) error {
	txhash, err := this.sdk.WasmVM.InvokeWasmVMSmartContract(this.gasPrice, this.gasLimit, signer, signer, this.contractAddress, method, param)
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
