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

package differs

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	pkgutil "github.com/snyk/snyk-docker-analyzer/pkg/util"
	"github.com/snyk/snyk-docker-analyzer/util"

	"github.com/sirupsen/logrus"
)

type ApkAnalyzer struct {
}

func (a ApkAnalyzer) Name() string {
	return "ApkAnalyzer"
}

// AptDiff compares the packages installed by apt-get.
func (a ApkAnalyzer) Diff(image1, image2 pkgutil.Image) (util.Result, error) {
	diff, err := singleVersionDiff(image1, image2, a)
	return diff, err
}

func (a ApkAnalyzer) Analyze(image pkgutil.Image) (util.Result, error) {
	analysis, err := singleVersionAnalysis(image, a)
	return analysis, err
}

func (a ApkAnalyzer) getPackages(image pkgutil.Image) (map[string]util.PackageInfo, error) {
	path := image.FSPath
	packages := make(map[string]util.PackageInfo)
	if _, err := os.Stat(path); err != nil {
		// invalid image directory path
		return packages, err
	}
	statusFile := filepath.Join(path, "lib/apk/db/installed")
	if _, err := os.Stat(statusFile); err != nil {
		// status file does not exist in this layer
		return packages, nil
	}
	if file, err := os.Open(statusFile); err == nil {
		// fmt.Printf("reading the apk db file")
		// make sure it gets closed
		defer file.Close()

		// create a new scanner and read the file line by line
		scanner := bufio.NewScanner(file)
		var curPkg string
		for scanner.Scan() {
			a.parseLine(scanner.Text(), &curPkg, packages)
		}
	} else {
		return packages, err
	}

	return packages, nil
}

func (a ApkAnalyzer) parseLine(text string, curPkg *string, packages map[string]util.PackageInfo) {
	line := strings.SplitN(text, ":", 2)
	if len(line) == 2 {
		key := line[0]
		value := line[1]

		getCurPkgInfo := func(name string) util.PackageInfo {
			info, ok := packages[name]
			if !ok {
				info = util.PackageInfo{}
			}
			return info
		}

		switch key {
		case "P":
			*curPkg = value
			break
		case "V":
			if packages[*curPkg].Version != "" {
				logrus.Warningln("Multiple versions of same package detected.  Diffing such multi-versioning not yet supported.")
			}
			curPkgInfo := getCurPkgInfo(*curPkg)

			curPkgInfo.Version = value
			packages[*curPkg] = curPkgInfo
			break
		case "p":
			curPkgInfo := getCurPkgInfo(*curPkg)

			for _, elem := range strings.Split(value, " ") {
				name := strings.Fields(elem)[0]
				name = strings.Split(name, "=")[0]
				curPkgInfo.Provides = append(curPkgInfo.Provides, name)
			}

			packages[*curPkg] = curPkgInfo

			break
		case "D", "r":
			curPkgInfo := getCurPkgInfo(*curPkg)
			if curPkgInfo.Deps == nil {
				curPkgInfo.Deps = map[string]interface{}{}
			}

			for _, dep := range strings.Split(value, " ") {
				name := strings.Fields(dep)[0]
				name = strings.Split(name, "=")[0]
				if !strings.HasPrefix(name, "!") {
					curPkgInfo.Deps[name] = nil
				}
			}

			packages[*curPkg] = curPkgInfo
			break
		}
	}
}
