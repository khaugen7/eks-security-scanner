/*
Copyright © 2025 Kyle Haugen kylehaugen.dev

*/
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/khaugen7/eks-security-scanner/internal/scanner"
)

var allChecks bool
var clusterName string

func init() {
	rootCmd.PersistentFlags().BoolVarP(&allChecks, "all", "a", false, "Run all checks")
	rootCmd.PersistentFlags().StringVarP(&clusterName, "cluster", "c", "", "Name of the EKS cluster to scan (required)")
	rootCmd.MarkPersistentFlagRequired("cluster")
}

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "eks-security-scanner",
	Short: "Scan your EKS cluster for common security misconfigurations",
	Run: func(cmd *cobra.Command, args []string) {
		if allChecks {
			fmt.Println("Running all checks...")
			// Run all scanners
			scanner.RunAuditCheck(clusterName)
			// scanner.RunPrivilegeCheck()
			// scanner.RunNamespaceCheck()
			// scanner.RunGraphCheck()
		} else {
			_ = cmd.Help()
		}
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}
