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

func TestParseDpkgStatusLine(t *testing.T) {
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
			line:        "Package: La-Croix",
			currPackage: "Tea",
			expPackage:  "La-Croix",
			packages:    map[string]util.PackageInfo{},
			expected:    map[string]util.PackageInfo{},
		},
		{
			descrip:     "Version line",
			line:        "Version: Lime",
			packages:    map[string]util.PackageInfo{},
			currPackage: "La-Croix",
			expPackage:  "La-Croix",
			expected:    map[string]util.PackageInfo{"La-Croix": {Version: "Lime"}},
		},
		{
			descrip:     "Version line with deb release info",
			line:        "Version: Lime+extra_lime",
			packages:    map[string]util.PackageInfo{},
			currPackage: "La-Croix",
			expPackage:  "La-Croix",
			expected:    map[string]util.PackageInfo{"La-Croix": {Version: "Lime+extra_lime"}},
		},
		{
			descrip:     "Source line",
			line:        "Source: libz1",
			packages:    map[string]util.PackageInfo{},
			currPackage: "zlib1g",
			expPackage:  "zlib1g",
			expected:    map[string]util.PackageInfo{"zlib1g": {Source: "libz1"}},
		},
		{
			descrip:     "Size line is ignored (vs original container-diff behaviours)",
			line:        "Installed-Size: 12",
			packages:    map[string]util.PackageInfo{},
			currPackage: "La-Croix",
			expPackage:  "La-Croix",
			expected:    map[string]util.PackageInfo{},
		},
		{
			descrip:     "Size line ignored also with pre-existing PackageInfo struct",
			line:        "Installed-Size: 12",
			packages:    map[string]util.PackageInfo{"La-Croix": {Version: "Lime"}},
			currPackage: "La-Croix",
			expPackage:  "La-Croix",
			expected:    map[string]util.PackageInfo{"La-Croix": {Version: "Lime"}},
		},
		{
			descrip:     "Depends line one value",
			line:        "Depends: libc6",
			packages:    map[string]util.PackageInfo{"make": {Version: "123"}},
			currPackage: "make",
			expPackage:  "make",
			expected:    map[string]util.PackageInfo{"make": {Version: "123", Deps: map[string]interface{}{"libc6": nil}}},
		},
		{
			descrip:     "Depends line several values",
			line:        "Depends: libc6",
			packages:    map[string]util.PackageInfo{"make": {Version: "123"}},
			currPackage: "make",
			expPackage:  "make",
			expected: map[string]util.PackageInfo{"make": {Version: "123", Deps: map[string]interface{}{
				"libc6": nil}}},
		},
		{
			descrip:     "Depends line several values",
			line:        "Depends: libtinfo5 (= 5.9+20140913-1+deb8u2), libc6 (>= 2.15)",
			packages:    map[string]util.PackageInfo{"libncurses5": {Version: "7"}},
			currPackage: "libncurses5",
			expPackage:  "libncurses5",
			expected: map[string]util.PackageInfo{"libncurses5": {Version: "7", Deps: map[string]interface{}{
				"libtinfo5": nil, "libc6": nil}}},
		},
		{
			descrip: "Pre-Depends line after Depends",
			line:    "Pre-Depends: multiarch-support, libtinfo5 (>= 5.9-3)",
			packages: map[string]util.PackageInfo{"libncurses5": {Version: "7", Deps: map[string]interface{}{
				"libtinfo5": nil, "libc6": nil}}},
			currPackage: "libncurses5",
			expPackage:  "libncurses5",
			expected: map[string]util.PackageInfo{"libncurses5": {Version: "7", Deps: map[string]interface{}{
				"multiarch-support": nil, "libtinfo5": nil, "libc6": nil}}},
		},
		{
			descrip:     "Depends with pipe",
			line:        "Depends: gcc | c-compiler, cpp, libc6-dev | libc-dev, file, autotools-dev",
			packages:    map[string]util.PackageInfo{"libtool": {Version: "2.4.2-1.11"}},
			currPackage: "libtool",
			expPackage:  "libtool",
			expected: map[string]util.PackageInfo{"libtool": {Version: "2.4.2-1.11", Deps: map[string]interface{}{
				"gcc":           nil,
				"c-compiler":    nil,
				"cpp":           nil,
				"libc6-dev":     nil,
				"libc-dev":      nil,
				"file":          nil,
				"autotools-dev": nil,
			}}},
		},
		{
			descrip:     "Provides line",
			line:        "Provides: libpng-dev, libpng12-0-dev, libpng3-dev",
			packages:    map[string]util.PackageInfo{},
			currPackage: "libpng12-dev",
			expPackage:  "libpng12-dev",
			expected: map[string]util.PackageInfo{"libpng12-dev": {Provides: []string{
				"libpng-dev", "libpng12-0-dev", "libpng3-dev"}}},
		},
	}

	for _, test := range testCases {
		a := AptAnalyzer{}
		currPackage := test.currPackage
		a.parseDpkgStatusLine(test.line, &currPackage, test.packages)
		if currPackage != test.expPackage {
			t.Errorf("Test case: %s:\nExpected current package to be: %s, but got: %s.",
				test.descrip, test.expPackage, currPackage)
		}
		if !reflect.DeepEqual(test.packages, test.expected) {
			t.Errorf("Test case: %s:\nExpected:\n%#v \nbut got:\n%#v",
				test.descrip, test.expected, test.packages)
		}
	}
}

func TestGetAptPackages(t *testing.T) {
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
			descrip: "no var/lib/apt/extended_states",
			path:    "testDirs/dpkgButNoAptExt",
			expected: map[string]util.PackageInfo{
				"pac1": {Version: "1.0"},
				"pac2": {Version: "2.0", Provides: []string{"the-pac"}},
				"pac3": {Version: "3.0", Source: "pac_ng", Deps: map[string]interface{}{
					"pac1":    nil,
					"libc":    nil,
					"libc6":   nil,
					"debconf": nil,
				}},
				"pac4": {Version: "1:2.29.2-1+deb9u1", Source: "pac4_ng"}},
		},
		{
			descrip: "packages in expected location",
			path:    "testDirs/packageOne",
			expected: map[string]util.PackageInfo{
				"pac1": {Version: "1.0"},
				"pac2": {Version: "2.0", Provides: []string{"the-pac"}, AutoInstalled: true},
				"pac3": {Version: "3.0", Source: "pac_ng", Deps: map[string]interface{}{
					"pac1":    nil,
					"libc":    nil,
					"libc6":   nil,
					"debconf": nil,
				}},
				"pac4": {Version: "1:2.29.2-1+deb9u1", Source: "pac4_ng"}},
		},
	}
	for _, test := range testCases {
		d := AptAnalyzer{}
		image := pkgutil.Image{FSPath: test.path}
		packages, err := d.getPackages(image)
		if err != nil && !test.err {
			t.Errorf("Test case: %s:\nGot unexpected error: %s", test.descrip, err)
		}
		if err == nil && test.err {
			t.Errorf("Test case: %s:\nExpected error but got none.", test.descrip)
		}
		if err == nil && !reflect.DeepEqual(packages, test.expected) {
			t.Errorf("Test Case: %s:\nExpected:\n%#v \nbut got:\n%#v\n",
				test.descrip, test.expected, packages)
		}
	}
}
