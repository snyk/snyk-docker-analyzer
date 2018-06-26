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
		{
			descrip:     "Depends line one value",
			line:        "D:musl-utils",
			packages:    map[string]util.PackageInfo{"libc-utils": {Version: "0.7.1-r0"}},
			currPackage: "libc-utils",
			expPackage:  "libc-utils",
			expected: map[string]util.PackageInfo{"libc-utils": {Version: "0.7.1-r0", Deps: map[string]interface{}{
				"musl-utils": nil,
			}}},
		},
		{
			descrip:     "Depends line multiple values",
			line:        "D:musl-utils other-utils",
			packages:    map[string]util.PackageInfo{"libc-utils": {Version: "0.7.1-r0"}},
			currPackage: "libc-utils",
			expPackage:  "libc-utils",
			expected: map[string]util.PackageInfo{"libc-utils": {Version: "0.7.1-r0", Deps: map[string]interface{}{
				"musl-utils":  nil,
				"other-utils": nil,
			}}},
		},
		{
			descrip:     "Depends line multiple values with colons",
			line:        "D:lua so:libc.so.0.9.32 so:libdl.so.0.9.32 so:libm.so.0.9.32 so:libncurses.so.5",
			packages:    map[string]util.PackageInfo{"vim": {Version: "7.3.754-r0"}},
			currPackage: "vim",
			expPackage:  "vim",
			expected: map[string]util.PackageInfo{"vim": {Version: "7.3.754-r0", Deps: map[string]interface{}{
				"lua":                nil,
				"so:libc.so.0.9.32":  nil,
				"so:libdl.so.0.9.32": nil,
				"so:libm.so.0.9.32":  nil,
				"so:libncurses.so.5": nil,
			}}},
		},
		{
			descrip:     "Depends line multiple values with exclusion",
			line:        "D:!uclibc-utils scanelf musl=1.1.18-r3 so:libc.musl-x86_64.so.1",
			packages:    map[string]util.PackageInfo{"musl-utils": {Version: "1.1.18-r3"}},
			currPackage: "musl-utils",
			expPackage:  "musl-utils",
			expected: map[string]util.PackageInfo{"musl-utils": {Version: "1.1.18-r3", Deps: map[string]interface{}{
				"scanelf": nil,
				"musl":    nil,
				"so:libc.musl-x86_64.so.1": nil,
			}}},
		},
		{
			descrip:     "Depends line (r)",
			line:        "r:libiconv uclibc-utils",
			packages:    map[string]util.PackageInfo{"musl-utils": {Version: "1.1.18-r3"}},
			currPackage: "musl-utils",
			expPackage:  "musl-utils",
			expected: map[string]util.PackageInfo{"musl-utils": {Version: "1.1.18-r3", Deps: map[string]interface{}{
				"libiconv":     nil,
				"uclibc-utils": nil,
			}}},
		},
		{
			descrip:     "Provides line single value",
			line:        "p:so:ld64-uClibc.so.0.9.32=0",
			packages:    map[string]util.PackageInfo{"libc": {Version: "0.9.33.2-r22"}},
			currPackage: "libc",
			expPackage:  "libc",
			expected: map[string]util.PackageInfo{"libc": {Version: "0.9.33.2-r22", Provides: []string{
				"so:ld64-uClibc.so.0.9.32",
			}}},
		},
		{
			descrip:     "Provides line multiple values",
			line:        "p:so:ld64-uClibc.so.0.9.32=0 so:libc.so.0.9.32=0 so:libcrypt.so.0.9.32=0",
			packages:    map[string]util.PackageInfo{"libc": {Version: "0.9.33.2-r22"}},
			currPackage: "libc",
			expPackage:  "libc",
			expected: map[string]util.PackageInfo{"libc": {Version: "0.9.33.2-r22", Provides: []string{
				"so:ld64-uClibc.so.0.9.32", "so:libc.so.0.9.32", "so:libcrypt.so.0.9.32",
			}}},
		},
	}

	for _, test := range testCases {
		a := ApkAnalyzer{}
		currPackage := test.currPackage
		a.parseLine(test.line, &currPackage, test.packages)
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
