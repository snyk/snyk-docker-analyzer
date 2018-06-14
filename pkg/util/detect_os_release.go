/*
Copyright 2018 Google, Inc. All rights reserved.

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
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// OSRelease OS Distro Name and Version
type OSRelease struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// DetectOSRelease Detect OS Distro Name and Version
func DetectOSRelease(imageFSPath string) (OSRelease, error) {
	// Modern linux
	osRelease, err := tryOsRelease(imageFSPath)

	// First generic fallback
	if os.IsNotExist(err) {
		osRelease, err = tryLSBRelease(imageFSPath)
	}

	// Fallbacks for specific older distros
	if os.IsNotExist(err) {
		osRelease, err = tryDebianVersion(imageFSPath)
	}
	if os.IsNotExist(err) {
		osRelease, err = tryAlpineRelease(imageFSPath)
	}
	if os.IsNotExist(err) {
		osRelease, err = tryOracleRelease(imageFSPath)
	}
	if os.IsNotExist(err) {
		osRelease, err = tryRedHatRelease(imageFSPath)
	}

	if os.IsNotExist(err) {
		err = fmt.Errorf("Failed to detect OS release")
	}

	// Oracle Linux identifies itself with "ol"
	if osRelease.Name == "ol" {
		osRelease.Name = "oracle"
	}
	return osRelease, err
}

func tryOsRelease(imageFSPath string) (OSRelease, error) {
	filePath := filepath.Join(imageFSPath, "etc/os-release")

	bytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		return OSRelease{}, err
	}

	text := string(bytes)

	idRe := regexp.MustCompile(`(?m)^ID=(.+)$`)
	idRes := idRe.FindAllStringSubmatch(text, -1)
	if len(idRes) != 1 {
		return OSRelease{}, fmt.Errorf("Failed to parse /etc/os-release")
	}
	id := strings.Replace(idRes[0][1], `"`, "", -1)

	versionRe := regexp.MustCompile(`(?m)^VERSION_ID=(.+)$`)
	versionRes := versionRe.FindAllStringSubmatch(text, -1)

	version := "unstable"
	if len(versionRes) == 1 {
		version = strings.Replace(versionRes[0][1], `"`, "", -1)
	}

	return OSRelease{id, version}, nil
}

func tryLSBRelease(imageFSPath string) (OSRelease, error) {
	filePath := filepath.Join(imageFSPath, "etc/lsb-release")

	bytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		return OSRelease{}, err
	}

	text := string(bytes)

	idRe := regexp.MustCompile(`(?m)^DISTRIB_ID=(.+)$`)
	idRes := idRe.FindAllStringSubmatch(text, -1)

	versionRe := regexp.MustCompile(`(?m)^DISTRIB_RELEASE=(.+)$`)
	versionRes := versionRe.FindAllStringSubmatch(text, -1)

	if len(versionRes) != 1 || len(idRes) != 1 {
		return OSRelease{}, fmt.Errorf("Failed to parse /etc/lsb-release")
	}

	id := strings.ToLower(strings.Replace(idRes[0][1], `"`, "", -1))
	version := strings.Replace(versionRes[0][1], `"`, "", -1)

	return OSRelease{id, version}, nil
}

func tryDebianVersion(imageFSPath string) (OSRelease, error) {
	filePath := filepath.Join(imageFSPath, "etc/debian_version")

	bytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		return OSRelease{}, err
	}

	text := strings.TrimSpace(string(bytes))
	if len(text) < 2 {
		return OSRelease{}, fmt.Errorf("Failed to parse /etc/debian_version")
	}

	id := "debian"
	version := strings.Split(text, ".")[0]

	return OSRelease{id, version}, nil
}

func tryAlpineRelease(imageFSPath string) (OSRelease, error) {
	filePath := filepath.Join(imageFSPath, "etc/alpine-release")

	bytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		return OSRelease{}, err
	}

	text := strings.TrimSpace(string(bytes))
	if len(text) < 2 {
		return OSRelease{}, fmt.Errorf("Failed to parse /etc/alpine-release")
	}

	id := "alpine"
	version := text

	return OSRelease{id, version}, nil
}

func tryRedHatRelease(imageFSPath string) (OSRelease, error) {
	filePath := filepath.Join(imageFSPath, "etc/redhat-release")

	bytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		return OSRelease{}, err
	}

	text := string(bytes)

	idRe := regexp.MustCompile(`(?m)^(\S+)`)
	idRes := idRe.FindAllStringSubmatch(text, -1)

	versionRe := regexp.MustCompile(`(?m)(\d+)\.`)
	versionRes := versionRe.FindAllStringSubmatch(text, -1)

	if len(versionRes) != 1 || len(idRes) != 1 {
		return OSRelease{}, fmt.Errorf("Failed to parse /etc/redhat-release")
	}

	id := strings.ToLower(strings.Replace(idRes[0][1], `"`, "", -1))
	version := strings.Replace(versionRes[0][1], `"`, "", -1)

	return OSRelease{id, version}, nil
}

func tryOracleRelease(imageFSPath string) (OSRelease, error) {
	filePath := filepath.Join(imageFSPath, "etc/oracle-release")

	bytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		return OSRelease{}, err
	}

	text := string(bytes)

	idRe := regexp.MustCompile(`(?m)^(\S+)`)
	idRes := idRe.FindAllStringSubmatch(text, -1)

	versionRe := regexp.MustCompile(`(?m)(\d+\.\d+)`)
	versionRes := versionRe.FindAllStringSubmatch(text, -1)

	if len(versionRes) != 1 || len(idRes) != 1 {
		return OSRelease{}, fmt.Errorf("Failed to parse /etc/oracle-release")
	}

	id := strings.ToLower(strings.Replace(idRes[0][1], `"`, "", -1))
	version := strings.Replace(versionRes[0][1], `"`, "", -1)

	return OSRelease{id, version}, nil
}
