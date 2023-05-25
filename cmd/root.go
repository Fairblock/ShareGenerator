package cmd

import (
	"github.com/spf13/cobra"
	"os"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "ShareGenerator",
	Short: "An executable for generating & deriving key share for fairyring",
	Long: `ShareGenerator is a CLI library for local fairyring testnet that
generate key share base on given number of validator & threshold.
It can also derive the key share for a given height.`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}
