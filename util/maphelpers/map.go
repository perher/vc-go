/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package maphelpers

// CopyMap performs shallow copy of map and nested maps.
func CopyMap(m map[string]any) map[string]any {
	cm := make(map[string]any)

	for k, v := range m {
		vm, ok := v.(map[string]any)
		if ok {
			cm[k] = CopyMap(vm)
		} else {
			cm[k] = v
		}
	}

	return cm
}
