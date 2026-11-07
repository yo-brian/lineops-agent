package release

import (
	"bytes"
	"errors"
	"log"
	"strings"
	"testing"
)

func TestTimedStagePreservesFailureWithoutLoggingSecrets(t *testing.T) {
	var output bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&output)
	defer log.SetOutput(previous)
	failure := errors.New("secret config payload")
	if got := timedStage("task-1", "config_check", func() error { return failure }); got != failure {
		t.Fatal("error changed")
	}
	if !strings.Contains(output.String(), "success=false") || !strings.Contains(output.String(), "elapsed_ms=") || strings.Contains(output.String(), failure.Error()) {
		t.Fatal(output.String())
	}
}
