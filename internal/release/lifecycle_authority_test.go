package release

import "testing"

func TestLifecycleReconcileAuthorityPreventsDelayedMutation(t *testing.T) {
	r := observationRequest()
	a := lifecycleReconcileAuthority{TaskID: r.TaskID, InstanceID: r.InstanceID, Epoch: r.Epoch, Fencing: r.Fencing, OriginalTaskID: r.Original.TaskID, OriginalFencing: r.Original.Fencing}
	if a.permitsLifecycle(r.Original) {
		t.Fatal("delayed original command retained execution authority")
	}
	if !a.permitsObservation(r) {
		t.Fatal("safe retry of exact observation rejected")
	}
	newer := r
	newer.TaskID = "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"
	newer.Fencing++
	if !a.permitsObservation(newer) {
		t.Fatal("fresh check of same original rejected")
	}
	old := r
	old.Fencing--
	if a.permitsObservation(old) {
		t.Fatal("older check passed authority barrier")
	}
	conflict := r
	conflict.TaskID = newer.TaskID
	if a.permitsObservation(conflict) {
		t.Fatal("different check reused authority fence")
	}
	newOperation := r.Original
	newOperation.Fencing = r.Fencing + 1
	if !a.permitsLifecycle(newOperation) {
		t.Fatal("fresh authorized operation rejected")
	}
	newOperation.Epoch = newer.TaskID
	if a.permitsLifecycle(newOperation) {
		t.Fatal("new epoch bypassed local authority")
	}
	a.OriginalFencing = a.Fencing
	if a.permitsObservation(r) || a.permitsLifecycle(newOperation) {
		t.Fatal("corrupt authority accepted")
	}
}
