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
	"testing"

	"github.com/stretchr/testify/assert"
)

func testDetection(t *testing.T, imageFSPath string, name string, version string) {
	osRelease, err := DetectOSRelease("../../tests/os_detection/" + imageFSPath)
	assert.Nil(t, err)
	assert.Equal(t, OSRelease{name, version}, osRelease)
}

func testFailedDetection(t *testing.T, imageFSPath string, expectedMessage string) {
	_, err := DetectOSRelease("../../tests/os_detection/" + imageFSPath)
	assert.EqualError(t, err, expectedMessage)
}

func TestSuccess(t *testing.T) {
	testDetection(t, "alpine_3_7_0", "alpine", "3.7.0") // uses /etc/os-release
	testDetection(t, "alpine_2_6_6", "alpine", "2.6.6") // uses /etc/alpine-release

	testDetection(t, "centos_7", "centos", "7") // uses /etc/os-release
	testDetection(t, "centos_6", "centos", "6") // uses /etc/redhat-release
	testDetection(t, "centos_5", "centos", "5") // uses /etc/redhat-release

	testDetection(t, "debian_unstable", "debian", "unstable") // uses /etc/os-release
	testDetection(t, "debian_9", "debian", "9")               // uses /etc/os-release
	testDetection(t, "debian_8", "debian", "8")               // uses /etc/os-release
	testDetection(t, "debian_7", "debian", "7")               // uses /etc/os-release
	testDetection(t, "debian_6", "debian", "6")               // uses /etc/debian_version

	testDetection(t, "oraclelinux_7_5", "oracle", "7.5")   // uses /etc/os-release
	testDetection(t, "oraclelinux_6_9", "oracle", "6.9")   // uses /etc/os-release
	testDetection(t, "oraclelinux_5_11", "oracle", "5.11") // uses /etc/oracle-release

	testDetection(t, "ubuntu_18_04", "ubuntu", "18.04") // uses /etc/os-release
	testDetection(t, "ubuntu_16_04", "ubuntu", "16.04") // uses /etc/os-release
	testDetection(t, "ubuntu_14_04", "ubuntu", "14.04") // uses /etc/os-release
	testDetection(t, "ubuntu_12_04", "ubuntu", "12.04") // uses /etc/os-release
	testDetection(t, "ubuntu_10_04", "ubuntu", "10.04") // uses /etc/lsb-release
}

func TestFailure(t *testing.T) {
	testFailedDetection(t, "unexpected", "Failed to detect OS release")
	testFailedDetection(t, "os_release_corrupt", "Failed to parse /etc/os-release")
	testFailedDetection(t, "lsb_release_corrupt", "Failed to parse /etc/lsb-release")
	testFailedDetection(t, "debian_version_corrupt", "Failed to parse /etc/debian_version")
	testFailedDetection(t, "alpine_release_corrupt", "Failed to parse /etc/alpine-release")
}
