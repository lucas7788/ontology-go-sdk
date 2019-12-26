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
	"github.com/ontio/ontology/common"
	"time"
)

func main() {
	sdk := ontology_go_sdk.NewOntologySdk()
	sdk.NewRpcClient().SetAddress("http://polaris1.ont.io:20336")
	sdk.NewRpcClient().SetAddress("http://127.0.0.1:20336")

	wallet, err := sdk.OpenWallet("./wallet3.dat")
	if err != nil {
		fmt.Println("OpenWallet error:", err)
		return
	}
	acc1, err := wallet.GetAccountByAddress("AbtTQJYKfQxq4UdygDsbLVjE8uRrJ2H3tP", []byte("111111"))
	if err != nil {
		fmt.Printf("OpenWallet error: %s", err)
		return
	}
	fmt.Println("acc1", acc1.Address.ToHexString())
	acc2, err := wallet.GetAccountByAddress("Ac9JHT6gFh6zxpfv4Q7ZPLD4xLhzcpRTWt", []byte("111111"))
	if err != nil {
		fmt.Printf("OpenWallet error: %s", err)
		return
	}

	code2 := "5cc56b096e6f7420666f756e646a00527ac40230316a51527ac40230326a52527ac40230336a53527ac408616c6c5f686173686a54527ac409616c6c5f61646d696e6a55527ac4681953797374656d2e53746f726167652e476574436f6e746578746a56527ac42241627454514a594b6651787134556479674473624c566a45387552724a324833745068204f6e746f6c6f67792e52756e74696d652e426173653538546f416464726573736a57527ac46c0126c56b6a00527ac46a51527ac46a52527ac46a51c304696e69747d9c7c75641500006a00c3069d03000000006e6c75666203006a51c30873657441646d696e7d9c7c756437006a52c3c0517d9c7c75516a00c306570f000000006e6a52c300c36a54527ac46a54c3516a00c3063304000000006e6c75666203006a51c30b637265617465546f7069637d9c7c75645e006a52c3c0547d9c7c75516a00c306570f000000006e6a52c300c36a55527ac46a52c351c36a56527ac46a52c352c36a57527ac46a52c353c36a58527ac46a58c36a57c36a56c36a55c3546a00c3064b05000000006e6c75666203006a51c310736574566f746572466f72546f7069637d9c7c756444006a52c3c0527d9c7c75516a00c306570f000000006e6a52c300c36a59527ac46a52c351c36a5a527ac46a5ac36a59c3526a00c3064007000000006e6c75666203006a51c30a6c69737441646d696e737d9c7c75641500006a00c306e104000000006e6c75666203006a51c30a6c697374546f706963737d9c7c75642a006a52c3c0007d9c7c75516a00c306570f000000006e006a00c3062108000000006e6c75666203006a51c308676574546f7069637d9c7c756437006a52c3c0517d9c7c75516a00c306570f000000006e6a52c300c36a59527ac46a59c3516a00c3068e08000000006e6c75666203006a51c30c676574546f706963496e666f7d9c7c756437006a52c3c0517d9c7c75516a00c306570f000000006e6a52c300c36a59527ac46a59c3516a00c306db08000000006e6c75666203006a51c309676574566f746572737d9c7c756437006a52c3c0517d9c7c75516a00c306570f000000006e6a52c300c36a59527ac46a59c3516a00c3066109000000006e6c75666203006a51c309766f7465546f7069637d9c7c756451006a52c3c0537d9c7c75516a00c306570f000000006e6a52c300c36a59527ac46a52c351c36a5b527ac46a52c352c36a5c527ac46a5cc36a5bc36a59c3536a00c306f109000000006e6c7566620300006c756658c56b6a00527ac46a51527ac46203006a00c357c3516a00c306fc0e000000006e6a00c355c36a00c356c3681253797374656d2e53746f726167652e4765746a53527ac46a53c3640a00006c75666203006a00c357c351c176c9681853797374656d2e52756e74696d652e53657269616c697a656a00c355c36a00c356c3681253797374656d2e53746f726167652e507574516c75665bc56b6a00527ac46a51527ac46a52527ac46203006a00c357c3516a00c306fc0e000000006e006a54527ac46a52c36a55527ac46a55c3c06a56527ac46a54c36a56c39f642b006a55c36a54c3c36a57527ac46a54c351936a54527ac46a57c3516a00c306bc0f000000006e62d1ff6a52c3681853797374656d2e52756e74696d652e53657269616c697a656a00c355c36a00c356c3681253797374656d2e53746f726167652e507574516c756657c56b6a00527ac46a51527ac46203006a00c355c36a00c356c3681253797374656d2e53746f726167652e4765746a52527ac46a52c3007d9c7c75640d0000c176c96c75666203006a52c3681a53797374656d2e52756e74696d652e446573657269616c697a656c75660115c56b6a00527ac46a51527ac46a52527ac46a53527ac46a54527ac46a55527ac46203006a52c3516a00c306fc0e000000006e6a52c3516a00c306840e000000006e516a00c306570f000000006e6a53c3a86a58527ac46a58c36a00c351c3526a00c306580e000000006e6a59527ac46a59c36a00c356c3681253797374656d2e53746f726167652e4765746a5a527ac46a5ac3640a00006c75666203006a53c36a59c36a00c356c3681253797374656d2e53746f726167652e5075746a58c36a00c352c3526a00c306580e000000006e6a5b527ac46a52c36a53c300c176c96a54c36a55c3000057c176c96a5c527ac46a5cc3681853797374656d2e52756e74696d652e53657269616c697a656a5bc36a00c356c3681253797374656d2e53746f726167652e50757400c176c96a5d527ac46a00c354c36a00c356c3681253797374656d2e53746f726167652e4765746a5e527ac46a5ec3642a006a5ec3681a53797374656d2e52756e74696d652e446573657269616c697a656a5d527ac46203006a5dc36a58c3c86a5dc3681853797374656d2e52756e74696d652e53657269616c697a656a00c354c36a00c356c3681253797374656d2e53746f726167652e5075746a53c36a58c30b637265617465546f70696353c1681553797374656d2e52756e74696d652e4e6f74696679516c75665dc56b6a00527ac46a51527ac46a52527ac46a53527ac46203006a52c36a00c352c3526a00c306580e000000006e6a55527ac46a55c36a00c356c3681253797374656d2e53746f726167652e4765746a56527ac46a56c3007d9c7c75640a00006c75666203006a56c3681a53797374656d2e52756e74696d652e446573657269616c697a656a57527ac46a57c300c3516a00c306fc0e000000006e6a53c36a57c3527bc46a57c3681853797374656d2e52756e74696d652e53657269616c697a656a55c36a00c356c3681253797374656d2e53746f726167652e507574516c756657c56b6a00527ac46a51527ac46203006a00c354c36a00c356c3681253797374656d2e53746f726167652e4765746a52527ac46a52c3007d9c7c75640d0000c176c96c75666225006a52c3681a53797374656d2e52756e74696d652e446573657269616c697a656c75666c756657c56b6a00527ac46a51527ac46a52527ac46203006a52c36a00c351c3526a00c306580e000000006e6a54527ac46a54c36a00c356c3681253797374656d2e53746f726167652e4765746c756659c56b6a00527ac46a51527ac46a52527ac46203006a52c36a00c352c3526a00c306580e000000006e6a54527ac46a54c36a00c356c3681253797374656d2e53746f726167652e4765746a55527ac46a55c3007d9c7c75640d0000c176c96c75666203006a55c3681a53797374656d2e52756e74696d652e446573657269616c697a656c75665ac56b6a00527ac46a51527ac46a52527ac46203006a52c36a00c352c3526a00c306580e000000006e6a54527ac46a54c36a00c356c3681253797374656d2e53746f726167652e4765746a55527ac46a55c3007d9c7c75640d0000c176c96c75666203006a55c3681a53797374656d2e52756e74696d652e446573657269616c697a656a56527ac46a56c352c36c75660112c56b6a00527ac46a51527ac46a52527ac46a53527ac46a54527ac46203006a53c3516a00c306fc0e000000006e6a53c36a52c3526a00c306280c000000006e516a00c306570f000000006e6a53c36a52c3526a00c3067c0d000000006e007d9c7c75516a00c306570f000000006e6a52c3516a00c306db08000000006e6a58527ac46a58c3c0577d9e7c75640a00006c7566620300681653797374656d2e52756e74696d652e47657454696d656a59527ac46a59c36a58c353c37d9f7c7576631000756a59c36a58c354c37da07c75640a00006c75666203006a54c36424006a58c355c36a52c36a53c3526a00c306a20b000000006e936a58c3557bc46221006a58c356c36a52c36a53c3526a00c306a20b000000006e936a58c3567bc46a52c36a00c352c3526a00c306580e000000006e6a5a527ac46a58c3681853797374656d2e52756e74696d652e53657269616c697a656a5ac36a00c356c3681253797374656d2e53746f726167652e5075746a52c36a53c3526a00c306aa0c000000006e6a53c36a52c309766f7465546f70696353c1681553797374656d2e52756e74696d652e4e6f74696679516c75665dc56b6a00527ac46a51527ac46a52527ac46a53527ac46203006a53c3516a00c3066109000000006e6a55527ac4006a56527ac46a55c36a57527ac46a57c3c06a58527ac46a56c36a58c39f6436006a57c36a56c3c36a59527ac46a56c351936a56527ac46a59c300c36a52c37d9c7c75640e006a59c351c36c756662030062c6ff006c75665dc56b6a00527ac46a51527ac46a52527ac46a53527ac46203006a52c3516a00c3066109000000006e6a55527ac4006a56527ac46a55c36a57527ac46a57c3c06a58527ac46a56c36a58c39f6432006a57c36a56c3c36a59527ac46a56c351936a56527ac46a59c300c36a53c37d9c7c75640a00516c756662030062caff006c75665cc56b6a00527ac46a51527ac46a52527ac46a53527ac46203006a53c36a00c353c3526a00c306580e000000006e6a55527ac46a55c36a00c356c3681253797374656d2e53746f726167652e4765746a56527ac400c176c96a57527ac46a56c3007d9e7c75642a006a56c3681a53797374656d2e52756e74696d652e446573657269616c697a656a57527ac46203006a57c36a52c3c86a57c3681853797374656d2e52756e74696d652e53657269616c697a656a55c36a00c356c3681253797374656d2e53746f726167652e5075746c756660c56b6a00527ac46a51527ac46a52527ac46a53527ac46203006a52c36a00c353c3526a00c306580e000000006e6a55527ac46a55c36a00c356c3681253797374656d2e53746f726167652e4765746a56527ac46a56c3007d9c7c75640a00006c75666275006a56c3681a53797374656d2e52756e74696d652e446573657269616c697a656a57527ac4006a58527ac46a57c36a59527ac46a59c3c06a5a527ac46a58c36a5ac39f6430006a59c36a58c3c36a5b527ac46a58c351936a58527ac46a5bc36a53c37d9c7c75640a00516c756662030062ccff006c756658c56b6a00527ac46a51527ac46a52527ac46a53527ac46203006a52c36a53c37e6a54527ac46a54c36c75665cc56b6a00527ac46a51527ac46a52527ac4620300006a00c306e104000000006e6a54527ac4006a55527ac46a54c36a56527ac46a56c3c06a57527ac46a55c36a57c39f6430006a56c36a55c3c36a58527ac46a55c351936a55527ac46a58c36a52c37d9c7c75640a00516c756662030062ccff006c756656c56b6a00527ac46a51527ac46a52527ac46203001641646472657373206973206e6f74207769746e6573736a52c3681b53797374656d2e52756e74696d652e436865636b5769746e657373526a00c306570f000000006e6c756656c56b6a00527ac46a51527ac46a52527ac46a51c3519c640600620b006a53527ac4621b001254686572652077617320616e206572726f726a53527ac46a52c3916421006a53c3681253797374656d2e52756e74696d652e4c6f676a53c3f06203006c756656c56b6a00527ac46a51527ac46a52527ac46203001a416464726573732068617320696e76616c6964206c656e6774686a52c3c001147d9c7c75526a00c306570f000000006e6c7566"
	code2Bs, _ := common.HexToBytes(code2)
	contractAddr := common.AddressFromVmCode(code2Bs)
	fmt.Println("contractAddr:", contractAddr.ToHexString())
	deployCode, err := sdk.GetSmartContract(contractAddr.ToHexString())
	if err != nil && err.Error() != "JsonRpcResponse error code:44004 desc:UNKNOWN CONTRACT result:\"UNKNOWN CONTRACT\"" {
		fmt.Printf("GetSmartContract error: %s", err)
		return
	}

	if deployCode == nil {
		hash, err := sdk.NeoVM.DeployNeoVMSmartContract(0, 210000000, acc1, true, code2,
			"name", "version", "author", "email", "desc")
		if err != nil {
			fmt.Printf("DeployNeoVMSmartContract error: %s", err)
			return
		}

		time.Sleep(time.Duration(6) * time.Second)
		event, err := sdk.GetSmartContractEvent(hash.ToHexString())
		if err != nil {
			fmt.Printf("GetSmartContractEvent error: %s", err)
			return
		}
		fmt.Println("deploy event:", event)
	}

	vote := &Vote{
		Sdk:          sdk,
		ContractAddr: contractAddr,
		Acc1:         acc1,
		Acc2:         acc2,
	}
	fmt.Println("")
	fmt.Println("******init****")
	vote.invoke("init", []interface{}{})

	fmt.Println("")
	fmt.Println("******setAdmin****")
	vote.invoke("setAdmin", []interface{}{[]interface{}{acc1.Address,acc2.Address}})

	fmt.Println("")
	fmt.Println("******listAdmin****")
	vote.preInvoke("listAdmin", []interface{}{})

	fmt.Println("")
	fmt.Println("******createTopic****")
	vote.invoke("createTopic", []interface{}{acc1.Address,"6",1577359509,1577366709})


	fmt.Println("")
	fmt.Println("******setVoterForTopic****")
	vote.invoke("setVoterForTopic", []interface{}{vote.TopicHash,
		[]interface{}{[]interface{}{acc1.Address, 1}, []interface{}{acc2.Address, 1}}})

	fmt.Println("")
	fmt.Println("******getVoters****")
	vote.preInvoke("getVoters", []interface{}{vote.TopicHash})


	fmt.Println("")
	fmt.Println("******voteTopic****")
	vote.invoke("voteTopic", []interface{}{vote.TopicHash, acc1.Address, true})


	fmt.Println("")
	fmt.Println("******listTopics****")
	vote.preInvoke("listTopics", []interface{}{})

	fmt.Println("")
	fmt.Println("******getTopic****")
	vote.preInvoke("getTopic", []interface{}{vote.TopicHash})

	fmt.Println("")
	fmt.Println("******getTopicInfo****")
	vote.preInvoke("getTopicInfo", []interface{}{vote.TopicHash})

	fmt.Println("")
	fmt.Println("******listTopics****")
	vote.preInvoke("listTopics", []interface{}{})

	fmt.Println("")
	fmt.Println("******getVoters****")
	vote.preInvoke("getVoters", []interface{}{vote.TopicHash})

	//fmt.Println("")
	//fmt.Println("******voteTopic****")
	//vote.invoke("voteTopic", []interface{}{vote.TopicHash, acc1.Address})
	//vote.invoke("voteTopic", []interface{}{vote.TopicHash, acc1.Address})
	//vote.invoke("voteTopic", []interface{}{vote.TopicHash, acc1.Address})
}

type Vote struct {
	Sdk          *ontology_go_sdk.OntologySdk
	ContractAddr common.Address
	Acc1         *ontology_go_sdk.Account
	Acc2         *ontology_go_sdk.Account
	TopicHash    []byte
}

func (v *Vote) invoke(method string, args []interface{}) {
	hash, err := v.Sdk.NeoVM.InvokeNeoVMContract(0, 2000000, v.Acc1, v.Acc1, v.ContractAddr,
		[]interface{}{method, args})
	if err != nil {
		fmt.Printf("InvokeNeoVMContract error: %s\n", err)
		return
	}
	time.Sleep(time.Duration(6) * time.Second)
	event, err := v.Sdk.GetSmartContractEvent(hash.ToHexString())
	if err != nil {
		fmt.Printf("GetSmartContractEvent error: %s", err)
		return
	}
	fmt.Println("Event notify:", event)
	if method == "createTopic" {
		for _, notify := range event.Notify {
			addr, _ := common.AddressFromHexString(notify.ContractAddress)
			if addr == v.ContractAddr {
				temp, _ := notify.States.([]interface{})
				t := temp[1].(string)
				tbs, _ := common.HexToBytes(t)
				v.TopicHash = tbs
				fmt.Println("Event notify:", temp)
			}
		}
	}
}

func (v *Vote) preInvoke(method string, args []interface{}) {
	res, err := v.Sdk.NeoVM.PreExecInvokeNeoVMContract(v.ContractAddr,
		[]interface{}{method, args})
	if err != nil {
		fmt.Printf("InvokeNeoVMContract error: %s\n", err)
		return
	}
	if method == "getTopicStatus" {
		r, _ := res.Result.ToString()
		fmt.Println("PreExecInvokeNeoVMContract result:", r)
	} else {
		fmt.Println("PreExecInvokeNeoVMContract result:", res.Result)
	}
}
