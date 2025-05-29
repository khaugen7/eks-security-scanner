/*
Copyright © 2025 Kyle Haugen kylehaugen.dev
*/
package cmd

import (
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/khaugen7/eks-security-scanner/internal/kube"
	"github.com/khaugen7/eks-security-scanner/internal/logger"
	"github.com/khaugen7/eks-security-scanner/internal/scanner"
)

var allChecks bool
var clusterName string
var outputFormat string
var namespace string
var verbose bool

func init() {
	rootCmd.PersistentFlags().BoolVarP(&allChecks, "all", "a", false, "Run all checks")
	rootCmd.PersistentFlags().StringVarP(&clusterName, "cluster", "c", "", "Name of the EKS cluster to scan (required)")
	rootCmd.MarkPersistentFlagRequired("cluster")
	rootCmd.PersistentFlags().StringVarP(&namespace, "namespace", "n", "", "Name of the namespace scan")
	rootCmd.PersistentFlags().StringVarP(&outputFormat, "format", "f", "ascii", "Output format: ascii or dot")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
}

var rootCmd = &cobra.Command{
	Use:   "eks-scanner",
	Short: "Scan your EKS cluster for common security misconfigurations",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		logger.Init(verbose)
	},
	Run: func(cmd *cobra.Command, args []string) {
		if allChecks {
			client := kube.GetClient()
			log.Infoln("Running all checks...")
			scanner.RunAuditCheck(clusterName, client)
			scanner.RunPrivilegeCheck(namespace, client)
			scanner.RunNamespaceCheck(namespace, client)
			scanner.RunGraphCheck(outputFormat, namespace, client)
		} else {
			_ = cmd.Help()
		}
	},
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}
