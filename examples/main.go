package main

import (
	"bufio"
	"fmt"
	"github.com/ontio/ontology-go-sdk"
	"github.com/ontio/ontology/core/payload"
	"github.com/ontio/ontology/core/types"
	"os"
	"strings"
	"sync"
)

var NUM = 16
var nodes = []string{"http://dappnode1.ont.io:20336", "http://dappnode2.ont.io:20336",
	"http://dappnode3.ont.io:20336", "http://dappnode4.ont.io:20336"}

func main() {
	testNet := "http://dappnode1.ont.io:20336"
	//testNet = "http://polaris4.ont.io:20336"
	sdk := ontology_go_sdk.NewOntologySdk()
	sdk.NewRpcClient().SetAddress(testNet)
	startBlockHeight := uint32(9550765)

	curBlockHeight, err := sdk.GetCurrentBlockHeight()
	if err != nil {
		fmt.Println(err)
		return
	}
	deltaHeight := curBlockHeight - startBlockHeight
	deltaHeight = deltaHeight / uint32(NUM)
	wait := new(sync.WaitGroup)
	for i := 0; i < NUM; i++ {
		wait.Add(1)
		go func(i int) {
			defer wait.Done()
			scanBlock(startBlockHeight+uint32(i)*deltaHeight, i, deltaHeight)
			fmt.Printf("finished, i: %d,start: %d, end: %d, \n", i, startBlockHeight+uint32(i)*deltaHeight, startBlockHeight+uint32(i)*deltaHeight+deltaHeight)
		}(i)
	}
	wait.Wait()
}

func scanBlock(blockHeight uint32, i int, deltaHeight uint32) {
	sdk := ontology_go_sdk.NewOntologySdk()
	index := i % 4
	sdk.NewRpcClient().SetAddress(nodes[index])
	fileName := fmt.Sprintf("txHash-%d.txt", i)
	f, err := os.Create(fileName)
	if err != nil {
		fmt.Println(err)
		return
	}
	w := bufio.NewWriter(f)
	defer func() {
		w.Flush()
		f.Close()
	}()
	endHeight := blockHeight + deltaHeight
	for {
		block, err := sdk.GetBlockByHeight(blockHeight)
		if err != nil {
			fmt.Println(err)
			return
		}
		if blockHeight > endHeight {
			return
		}
		fmt.Printf("currentBlockHeight: %d\n", blockHeight)
		for _, tx := range block.Transactions {
			if tx.TxType == types.InvokeWasm {
				invokeCode := tx.Payload.(*payload.InvokeCode)
				if strings.Contains(string(invokeCode.Code), "setNewMarketID") {
					txHash := tx.Hash()
					txHashStr := txHash.ToHexString()
					fmt.Printf("txhash: %s\n", txHashStr)
					lineStr := fmt.Sprintf("txHash:%s, payer: %s", txHashStr, tx.Payer.ToBase58())
					fmt.Fprintln(w, lineStr)
				}
			}
		}
		blockHeight += 1
	}
}
