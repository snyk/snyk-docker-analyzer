/*
Copyright 2017 Google, Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cmd

import (
	goflag "flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/snyk/snyk-docker-analyzer/differs"
	pkgutil "github.com/snyk/snyk-docker-analyzer/pkg/util"
	"github.com/snyk/snyk-docker-analyzer/util"

	"github.com/docker/docker/client"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var json bool
var save bool
var types diffTypes
var noCache bool

var LogLevel string
var format string

type validatefxn func(args []string) error

var RootCmd = &cobra.Command{
	Use:   "snyk-docker-analyzer",
	Short: "snyk-docker-analyzer is a tool for analyzing and comparing container images",
	Long:  "snyk-docker-analyzer is a CLI tool for analyzing and comparing container images.",
	PersistentPreRun: func(c *cobra.Command, s []string) {
		ll, err := logrus.ParseLevel(LogLevel)

		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		logrus.SetLevel(ll)
	},
}

func outputResults(imageId string, osRelease pkgutil.OSRelease, resultMap map[string]util.Result) {
	// Outputs diff/analysis results in alphabetical order by analyzer name
	sortedTypes := []string{}
	for analyzerType := range resultMap {
		sortedTypes = append(sortedTypes, analyzerType)
	}
	sort.Strings(sortedTypes)

	results := make([]interface{}, len(resultMap))
	for i, analyzerType := range sortedTypes {
		result := resultMap[analyzerType]
		results[i] = result.OutputStruct()
	}
	output := map[string]interface{}{
		"imageId":   imageId,
		"osRelease": osRelease,
		"results":   results,
	}
	err := util.JSONify(output)
	if err != nil {
		logrus.Error(err)
	}
}

func validateArgs(args []string, validatefxns ...validatefxn) error {
	for _, validatefxn := range validatefxns {
		if err := validatefxn(args); err != nil {
			return err
		}
	}
	return nil
}

func checkIfValidAnalyzer(_ []string) error {
	if len(types) == 0 {
		types = []string{"apt", "rpm", "apk"}
	}
	for _, name := range types {
		if _, exists := differs.Analyzers[name]; !exists {
			return fmt.Errorf("Argument %s is not a valid analyzer", name)
		}
	}
	return nil
}

func getPrepperForImage(image string) (pkgutil.Prepper, error) {
	cli, err := client.NewEnvClient()
	if err != nil {
		return nil, err
	}

	if !strings.Contains(image, ":") {
		image = image + ":latest"
	}

	return &pkgutil.DaemonPrepper{
		Source: image,
		Client: cli,
	}, nil
}

// func cacheDir() (string, error) {
// 	dir, err := homedir.Dir()
// 	if err != nil {
// 		return "", err
// 	}
// 	rootDir := filepath.Join(dir, ".snyk-docker-analyzer")
// 	return filepath.Join(rootDir, "cache"), nil
// }

func init() {
	RootCmd.PersistentFlags().StringVarP(&LogLevel, "verbosity", "v", "warning", "This flag controls the verbosity of snyk-docker-analyzer.")
	pflag.CommandLine.AddGoFlagSet(goflag.CommandLine)
}

// Define a type named "diffSlice" as a slice of strings
type diffTypes []string

// Now, for our new type, implement the two methods of
// the flag.Value interface...
// The first method is String() string
func (d *diffTypes) String() string {
	return strings.Join(*d, ",")
}

// The second method is Set(value string) error
func (d *diffTypes) Set(value string) error {
	// Dedupe repeated elements.
	for _, t := range *d {
		if t == value {
			return nil
		}
	}
	*d = append(*d, value)
	return nil
}

func (d *diffTypes) Type() string {
	return "Diff Types"
}

func addSharedFlags(cmd *cobra.Command) {
	cmd.Flags().BoolVarP(&save, "save", "s", false, "Set this flag to save rather than remove the final image filesystems on exit.")
}
