/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	// "github.com/khaugen7/eks-security-scanner/internal/scanner"

)

// privilegeCmd represents the privilege command
var privilegeCmd = &cobra.Command{
	Use:   "privilege",
	Short: "Scans pods for privileged permissions or root access.",
	Long: `Scans all Pods and highlights:
- privileged: true or hostPID/hostNetwork/hostPath
- Containers running as root
- Dangerous Linux capabilities`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Running privileges scan...")
		// scanner.RunPrivilegeCheck()
	},
}

func init() {
	rootCmd.AddCommand(privilegeCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// privilegeCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// privilegeCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
