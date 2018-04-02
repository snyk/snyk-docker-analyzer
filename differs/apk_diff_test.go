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
	"reflect"
	"testing"

	pkgutil "github.com/snyk/snyk-docker-analyzer/pkg/util"
	"github.com/snyk/snyk-docker-analyzer/util"
)

func TestApkParseLine(t *testing.T) {
	testCases := []struct {
		descrip     string
		line        string
		packages    map[string]util.PackageInfo
		currPackage string
		expPackage  string
		expected    map[string]util.PackageInfo
	}{
		{
			descrip:    "Not applicable line",
			line:       "Garbage: garbage info",
			packages:   map[string]util.PackageInfo{},
			expPackage: "",
			expected:   map[string]util.PackageInfo{},
		},
		{
			descrip:     "Package line",
			line:        "P:La-Croix",
			currPackage: "Tea",
			expPackage:  "La-Croix",
			packages:    map[string]util.PackageInfo{},
			expected:    map[string]util.PackageInfo{},
		},
		{
			descrip:     "Version line",
			line:        "V:Lime",
			packages:    map[string]util.PackageInfo{},
			currPackage: "La-Croix",
			expPackage:  "La-Croix",
			expected:    map[string]util.PackageInfo{"La-Croix": {Version: "Lime"}},
		},
		{
			descrip:     "Version line with deb release info",
			line:        "V:Lime+extra_lime",
			packages:    map[string]util.PackageInfo{},
			currPackage: "La-Croix",
			expPackage:  "La-Croix",
			expected:    map[string]util.PackageInfo{"La-Croix": {Version: "Lime+extra_lime"}},
		},
	}

	for _, test := range testCases {
		a := ApkAnalyzer{}
		currPackage := a.parseLine(test.line, test.currPackage, test.packages)
		if currPackage != test.expPackage {
			t.Errorf("Expected current package to be: %s, but got: %s.", test.expPackage, currPackage)
		}
		if !reflect.DeepEqual(test.packages, test.expected) {
			t.Errorf("Expected: %#v but got: %#v", test.expected, test.packages)
		}
	}
}

func TestGetApkPackages(t *testing.T) {
	testCases := []struct {
		descrip  string
		path     string
		expected map[string]util.PackageInfo
		err      bool
	}{
		{
			descrip:  "no directory",
			path:     "testDirs/notThere",
			expected: map[string]util.PackageInfo{},
			err:      true,
		},
		{
			descrip:  "no packages",
			path:     "testDirs/noPackages",
			expected: map[string]util.PackageInfo{},
		},
		{
			descrip: "packages in expected location",
			path:    "testDirs/packageOne",
			expected: map[string]util.PackageInfo{
				"pac1": {Version: "1.0"},
				"pac2": {Version: "2.0"}},
		},
	}
	for _, test := range testCases {
		d := ApkAnalyzer{}
		image := pkgutil.Image{FSPath: test.path}
		packages, err := d.getPackages(image)
		if err != nil && !test.err {
			t.Errorf("Got unexpected error: %s", err)
		}
		if err == nil && test.err {
			t.Errorf("Expected error but got none.")
		}
		if !reflect.DeepEqual(packages, test.expected) {
			t.Errorf("Expected: %v but got: %v", test.expected, packages)
		}
	}
}
