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
	"strconv"
	"strings"

	pkgutil "github.com/snyk/snyk-docker-analyzer/pkg/util"
	"github.com/snyk/snyk-docker-analyzer/util"

	"github.com/sirupsen/logrus"
)

type AptAnalyzer struct {
}

func (a AptAnalyzer) Name() string {
	return "AptAnalyzer"
}

// Diff compares the packages installed by apt-get.
func (a AptAnalyzer) Diff(image1, image2 pkgutil.Image) (util.Result, error) {
	diff, err := singleVersionDiff(image1, image2, a)
	return diff, err
}

func (a AptAnalyzer) Analyze(image pkgutil.Image) (util.Result, error) {
	analysis, err := singleVersionAnalysis(image, a)
	return analysis, err
}

func (a AptAnalyzer) getPackages(image pkgutil.Image) (map[string]util.PackageInfo, error) {
	path := image.FSPath
	if _, err := os.Stat(path); err != nil {
		// invalid image directory path
		return nil, err
	}

	pkgs, err := a.parseDpkgStatus(path)
	if err != nil {
		return nil, err
	}

	autoInstalledPkgs, err := a.parseAptExtStates(path)
	if err != nil {
		// let's not fail if we failed to parse the extended states
		return pkgs, nil
	}

	for _, pkgName := range autoInstalledPkgs {
		if pkg, ok := pkgs[pkgName]; ok {
			pkg.AutoInstalled = true
			pkgs[pkgName] = pkg
		}
	}

	return pkgs, err
}

func (a AptAnalyzer) parseAptExtStates(imagePath string) ([]string, error) {
	autoInstalledPkgs := []string{}
	fpath := filepath.Join(imagePath, "var/lib/apt/extended_states")
	if _, err := os.Stat(fpath); err != nil {
		return nil, err
	}

	file, err := os.Open(fpath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var curPkg string
	for scanner.Scan() {
		a.parseAptExtStatesLine(scanner.Text(), &curPkg, &autoInstalledPkgs)
	}

	return autoInstalledPkgs, nil
}

func (a AptAnalyzer) parseAptExtStatesLine(text string, curPkg *string, autoInstalledPkgs *[]string) {
	line := strings.Split(text, ": ")
	if len(line) == 2 {
		key := line[0]
		value := line[1]

		switch key {
		case "Package":
			*curPkg = value
			break
		case "Auto-Installed":
			autoInstalled, err := strconv.Atoi(value)
			if err != nil {
				break
			}
			if autoInstalled == 1 {
				*autoInstalledPkgs = append(*autoInstalledPkgs, *curPkg)
			}
		}
	}
}

func (a AptAnalyzer) parseDpkgStatus(imagePath string) (map[string]util.PackageInfo, error) {
	packages := make(map[string]util.PackageInfo)
	fpath := filepath.Join(imagePath, "var/lib/dpkg/status")
	if _, err := os.Stat(fpath); err != nil {
		// status file does not exist in this layer
		return packages, nil
	}

	file, err := os.Open(fpath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var curPkg string
	for scanner.Scan() {
		a.parseDpkgStatusLine(scanner.Text(), &curPkg, packages)
	}

	return packages, nil
}

func (a AptAnalyzer) parseDpkgStatusLine(text string, curPkg *string, packages map[string]util.PackageInfo) {
	line := strings.Split(text, ": ")
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
		case "Package":
			*curPkg = value
			break
		case "Source":
			source := strings.Fields(value)[0]

			curPkgInfo := getCurPkgInfo(*curPkg)
			curPkgInfo.Source = source
			packages[*curPkg] = curPkgInfo
			break
		case "Provides":
			curPkgInfo := getCurPkgInfo(*curPkg)

			for _, elem := range strings.Split(value, ",") {
				name := strings.Fields(elem)[0]
				curPkgInfo.Provides = append(curPkgInfo.Provides, name)
			}

			packages[*curPkg] = curPkgInfo
			break
		case "Version":
			if packages[*curPkg].Version != "" {
				logrus.Warningln("Multiple versions of same package detected.  Diffing such multi-versioning not yet supported.")
				break
			}

			curPkgInfo := getCurPkgInfo(*curPkg)

			curPkgInfo.Version = value
			packages[*curPkg] = curPkgInfo
			break
		case "Depends", "Pre-Depends":
			curPkgInfo := getCurPkgInfo(*curPkg)
			if curPkgInfo.Deps == nil {
				curPkgInfo.Deps = map[string]interface{}{}
			}

			for _, depElem := range strings.Split(value, ",") {
				for _, dep := range strings.Split(depElem, "|") {
					name := strings.Fields(dep)[0]
					curPkgInfo.Deps[name] = nil
				}
			}

			packages[*curPkg] = curPkgInfo
			break
		}
	}
}
