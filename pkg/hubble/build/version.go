// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package build

import (
	"fmt"

	"github.com/cilium/cilium/pkg/version"
)

var (
	// ServerVersion reports version information for Hubble server.
	ServerVersion Version
	// RelayVersion reports version information for Hubble Relay.
	RelayVersion Version
)

func init() {
	ciliumVersion := version.GetCiliumVersion()
	ServerVersion = Version{
		component: "cilium",
		Core:      ciliumVersion.Version,
		Revision:  ciliumVersion.Revision,
	}
	RelayVersion = Version{
		component: "hubble-relay",
		Core:      ciliumVersion.Version,
		Revision:  ciliumVersion.Revision,
	}
}

// Version defines a detailed Hubble component version.
type Version struct {
	// component is the Hubble component (eg: hubble, hubble-relay).
	component string
	// Core represents the core version (eg: 1.9.0).
	Core string
	// Revision is the software revision, typically a Git commit SHA.
	Revision string
}

func (v Version) String() string {
	if v.component == "" {
		return ""
	}
	s := v.component
	if v.Core == "" {
		return s
	}
	s = fmt.Sprintf("%s v%s", s, v.Core)
	if v.Revision != "" {
		s = fmt.Sprintf("%s-g%s", s, v.Revision)
	}
	return s
}
