package release

import (
	"testing"
	"time"
)

func TestLifecycleIdentityAndReceipt(t *testing.T) {
	r := LifecycleRequest{TaskID: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", InstanceID: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", Epoch: "cccccccc-cccc-cccc-cccc-cccccccccccc", Kind: "install_singbox", Fencing: 1}
	if !r.Valid() {
		t.Fatal("valid request rejected")
	}
	for _, mutate := range []func(*LifecycleRequest){func(x *LifecycleRequest) { x.InstanceID = "../../etc" }, func(x *LifecycleRequest) { x.Kind = "shell" }, func(x *LifecycleRequest) { x.Fencing = 0 }, func(x *LifecycleRequest) { x.Fencing = 1 << 63 }, func(x *LifecycleRequest) { x.Epoch = "" }} {
		bad := r
		mutate(&bad)
		if bad.Valid() {
			t.Fatal("unsafe request accepted", bad)
		}
	}
	result := LifecycleResult{TaskID: r.TaskID, InstanceID: r.InstanceID, Epoch: r.Epoch, Kind: r.Kind, Fencing: r.Fencing, State: "succeeded", FinishedAt: time.Now()}
	if !result.Valid() {
		t.Fatal("valid receipt rejected")
	}
	result.FinishedAt = time.Time{}
	if result.Valid() {
		t.Fatal("undated receipt accepted")
	}
}
