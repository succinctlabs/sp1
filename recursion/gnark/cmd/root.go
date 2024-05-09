package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var CONSTRAINTS_JSON_FILE string = "constraints_groth16.json"
var WITNESS_JSON_FILE string = "witness_groth16.json"
var VERIFIER_CONTRACT_PATH string = "SP1Verifier.sol"
var CIRCUIT_PATH string = "circuit_groth16.bin"
var VK_PATH string = "vk_groth16.bin"
var PK_PATH string = "pk_groth16.bin"

var rootCmd = &cobra.Command{
	Use: "sp1-recursion-gnark",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("SP1 Recursion Gnark CLI")
	},
}

func init() {
	rootCmd.AddCommand(buildCmd)
	rootCmd.AddCommand(proveCmd)
	rootCmd.AddCommand(verifyCmd)
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
