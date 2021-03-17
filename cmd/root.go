package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/viper"
)

var cfgFile string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "qualys_parser",
	Short: "Parse the qualys report",
	Long: `A tool to parse the qualys report by giving
	Example:
	qualys_parser -i report.csv
	qualys_parser -i report.csv -d
	qualys_parser -i report.csv --ip
	qualys_parser -i report.csv --host 172.31.251.19 --ip
	qualys_parser -i report.csv --pkg git-man
	qualys_parser -i real.csv -l
	`,
	Run: func(cmd *cobra.Command, args []string) {
		inputFileName, _ = cmd.Flags().GetString("input")
		outputFileName, _ = cmd.Flags().GetString("output")
		detailSet, _ = cmd.Flags().GetBool("detail")
		if outputFileName == "" {
			outputFileName = "parsing_result.json"
		}
		hostIp, _ = cmd.Flags().GetString("host")
		listOnly, _ = cmd.Flags().GetBool("list")
		pkgName, _ = cmd.Flags().GetString("pkg")
		reportByIp, _ := cmd.Flags().GetBool("ip")
		if reportByIp {
			GetVulnerabilitiesByIP()
		} else {
			GetVulnerabilities()
		}
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringP("input", "i", "", "Specify the report to parse")
	_ = rootCmd.MarkPersistentFlagRequired("input")
	rootCmd.PersistentFlags().StringP("output", "o", "", "Specify the name of the output file")
	rootCmd.PersistentFlags().String("host", "", "Specify the host ip address to print out vulnerable package")
	rootCmd.PersistentFlags().StringP("pkg", "p", "", "Specify the package to print out the ip with that vulnerable package")
	rootCmd.PersistentFlags().BoolP("list", "l", false, "Specify whether we want just a pure list of IPs or packages")
	rootCmd.PersistentFlags().BoolP("detail", "d", false, "Specify whether to add package detail or not")
	rootCmd.PersistentFlags().Bool("ip", false, "Specify whether to receive the report based on ip address or not")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// Search config in home directory with name ".find_repo_owner" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigName(".find_repo_owner")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
}
