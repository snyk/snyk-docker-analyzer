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

package util

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pkgutil "github.com/snyk/snyk-docker-analyzer/pkg/util"
)

func TestUnTar(t *testing.T) {
	testCases := []struct {
		descrip   string
		tarPath   string
		target    string
		expected  string
		starter   string
		whitelist []string
		err       bool
		skipDiff  bool
	}{
		{
			descrip:  "Tar with files",
			tarPath:  "testTars/la-croix1.tar",
			target:   "testTars/la-croix1",
			expected: "testTars/la-croix1-actual",
		},
		{
			descrip:  "Tar with folders with files",
			tarPath:  "testTars/la-croix2.tar",
			target:   "testTars/la-croix2",
			expected: "testTars/la-croix2-actual",
		},
		{
			descrip:  "Tar with folders with files and a tar file",
			tarPath:  "testTars/la-croix3.tar",
			target:   "testTars/la-croix3",
			expected: "testTars/la-croix3-actual",
		},
		{
			descrip:  "Tar with .wh.'s",
			tarPath:  "testTars/la-croix-wh.tar",
			target:   "testTars/la-croix-wh",
			expected: "testTars/la-croix-wh-actual",
			starter:  "testTars/la-croix-starter",
		},
		{
			descrip:  "Files updated",
			tarPath:  "testTars/la-croix-update.tar",
			target:   "testTars/la-croix-update",
			expected: "testTars/la-croix-update-actual",
			starter:  "testTars/la-croix-starter",
		},
		{
			descrip:  "Dir updated",
			tarPath:  "testTars/la-croix-dir-update.tar",
			target:   "testTars/la-croix-dir-update",
			expected: "testTars/la-croix-dir-update-actual",
			starter:  "testTars/la-croix-starter",
		},
		{
			descrip:   "Tar with whitelist",
			tarPath:   "testTars/la-croix2.tar",
			target:    "testTars/la-croix-whitelist",
			expected:  "testTars/la-croix1-actual",
			whitelist: []string{"testTars/la-croix-whitelist/nest"},
		},
		{
			descrip:  "Tar with evil symlink",
			tarPath:  "testTars/symlink-invalid.tar",
			target:   "testTars/symlink-invalid",
			err:      true,
			skipDiff: true,
		},
	}
	for _, test := range testCases {
		remove := true
		if test.starter != "" {
			CopyDir(test.starter, test.target)
		}
		r, err := os.Open(test.tarPath)
		if err != nil {
			t.Errorf("Error opening tar: %s", err)
		}
		if err = pkgutil.UnTar(r, test.target, test.whitelist); err != nil && !test.err {
			t.Errorf(test.descrip, "Got unexpected error: %s", err)
			remove = false
		}
		if err == nil && test.err {
			t.Errorf(test.descrip, "Expected error but got none: %s", err)
			remove = false
		}
		if !test.skipDiff && !dirEquals(test.expected, test.target) {
			t.Error(test.descrip, ": Directory created not correct structure.")
			remove = false
		}
		if remove {
			os.RemoveAll(test.target)
		}
	}
}

// Copies file source to destination dest.
func CopyFile(source string, dest string) (err error) {
	sf, err := os.Open(source)
	if err != nil {
		return err
	}
	defer sf.Close()
	df, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer df.Close()
	_, err = io.Copy(df, sf)
	if err == nil {
		si, err := os.Stat(source)
		if err != nil {
			err = os.Chmod(dest, si.Mode())
		}

	}

	return nil
}

// Recursively copies a directory tree, attempting to preserve permissions.
// Source directory must exist, destination directory must *not* exist.
func CopyDir(source string, dest string) (err error) {

	// get properties of source dir
	fi, err := os.Stat(source)
	if err != nil {
		return err
	}

	if !fi.IsDir() {
		return errors.New("Source not a directory")
	}

	// ensure dest dir does not already exist

	_, err = os.Open(dest)
	if !os.IsNotExist(err) {
		return errors.New("Destination already exists")
	}

	// create dest dir

	err = os.MkdirAll(dest, fi.Mode())
	if err != nil {
		return err
	}

	entries, err := ioutil.ReadDir(source)

	for _, entry := range entries {

		sfp := source + "/" + entry.Name()
		dfp := dest + "/" + entry.Name()
		if entry.IsDir() {
			err = CopyDir(sfp, dfp)
			if err != nil {
				log.Println(err)
			}
		} else {
			// perform copy
			err = CopyFile(sfp, dfp)
			if err != nil {
				log.Println(err)
			}
		}

	}
	return nil
}

func TestIsTar(t *testing.T) {
	testCases := []struct {
		input    string
		expected bool
	}{
		{input: "/testTar/la-croix1.tar", expected: true},
		{input: "/testTar/la-croix1-actual", expected: false},
	}
	for _, test := range testCases {
		actual := pkgutil.IsTar(test.input)
		if test.expected != actual {
			t.Errorf("Expected: %t but got: %t", test.expected, actual)
		}
	}
}

func dirEquals(actual string, path string) bool {
	d1, _ := pkgutil.GetDirectory(actual, true)
	d2, _ := pkgutil.GetDirectory(path, true)
	diff, same := DiffDirectory(d1, d2)
	if !same {
		fmt.Printf("%v", diff)
	}
	return same
}

func TestSymlinks(t *testing.T) {
	remove := true
	target := "testTars/symlink-valid"
	starter := "testTars/symlink-valid-starter"
	r, err := os.Open("testTars/symlink-valid.tar")
	if err != nil {
		t.Errorf("Error opening tar: %s", err)
	}
	err = CopyDir(starter, target)
	if err != nil {
		t.Errorf("Failed to copy starter: %s", err)
		remove = false
	}
	err = pkgutil.UnTar(r, target, []string{})
	if err != nil {
		t.Errorf("Got unexpected error: %s", err)
		remove = false
	}
	var destination string
	if err == nil {
		destination, err = os.Readlink(filepath.Join(target, "foo/bar.txt"))
	}
	if destination != "../bar.txt" {
		t.Errorf("Unexpected symlink destination: %s", destination)
		remove = true
	}
	if remove {
		os.RemoveAll(target)
	}
}

func TestSymlinksCaseInsensitive(t *testing.T) {
	remove := true
	target := "testTars/symlink-case-sensitive"
	starter := "testTars/symlink-case-sensitive-starter"
	r, err := os.Open("testTars/symlink-case-sensitive.tar")
	if err != nil {
		t.Errorf("Error opening tar: %s", err)
	}
	err = CopyDir(starter, target)
	if err != nil {
		t.Errorf("Failed to copy starter: %s", err)
		remove = false
	}
	err = pkgutil.UnTar(r, target, []string{})
	if err != nil {
		t.Errorf("Got unexpected error: %s", err)
		remove = false
	}
	var bytes []byte
	bytes, err = ioutil.ReadFile(filepath.Join(target, "foo/bar.txt"))
	if err != nil {
		t.Errorf("Failed to read sample file: %s", err)
		remove = false
	}

	text := string(bytes)
	if !strings.HasPrefix(text, "new") {
		t.Errorf("Expected sample file to be replace, but saw: %s", text)
		remove = false
	}

	if remove {
		os.RemoveAll(target)
	}
}
