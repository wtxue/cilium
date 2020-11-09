// Copyright 2020 Authors of Hubble
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

// +build !privileged_tests

package filters

import (
	"context"
	"testing"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/monitor/api"

	"github.com/stretchr/testify/assert"
)

func TestNodeFilter(t *testing.T) {
	tests := []struct {
		name            string
		nodeName        []string
		wantErr         bool
		wantErrContains string
		want            map[string]bool
	}{
		{
			name: "empty",
			want: map[string]bool{
				"k8s1": true,
			},
		},
		{
			name:     "literal",
			nodeName: []string{"k8s1"},
			want: map[string]bool{
				"k8s1": true,
				"k8s2": false,
			},
		},
		{
			name:     "literals",
			nodeName: []string{"k8s1", "runtime1"},
			want: map[string]bool{
				"k8s1":     true,
				"runtime1": true,
			},
		},
		{
			name:     "pattern",
			nodeName: []string{"k8s*"},
			want: map[string]bool{
				"k8s1":     true,
				"runtime1": false,
			},
		},
		{
			name:     "doublestar_pattern",
			nodeName: []string{"cluster-name/**.com"},
			want: map[string]bool{
				"cluster-name/foo.com":     true,
				"cluster-name/foo.bar.com": true,
				"cluster-name/foo.com.org": false,
			},
		},
		{
			name:            "invalid_pattern",
			nodeName:        []string{"cluster_name"},
			wantErr:         true,
			wantErrContains: "invalid byte in node name pattern",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ff := []*flowpb.FlowFilter{
				{
					EventType: []*flowpb.EventTypeFilter{
						{
							Type: api.MessageTypeAccessLog,
						},
					},
					NodeName: tt.nodeName,
				},
			}
			fl, err := BuildFilterList(context.Background(), ff, []OnBuildFilter{&NodeNameFilter{}})
			if tt.wantErr {
				assert.Error(t, err)
				if tt.wantErrContains != "" {
					assert.Contains(t, err.Error(), tt.wantErrContains)
				}
				return
			}

			for nodeName, want := range tt.want {
				ev := &v1.Event{
					Event: &flowpb.Flow{
						EventType: &flowpb.CiliumEventType{
							Type: api.MessageTypeAccessLog,
						},
						NodeName: nodeName,
					},
				}
				assert.Equal(t, want, fl.MatchOne(ev), nodeName)
			}
		})
	}
}
