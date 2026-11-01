package gitproxy

import (
	"testing"

	"github.com/xcwds/valet/internal/audit"
	"github.com/xcwds/valet/internal/connector"
	"github.com/xcwds/valet/internal/jobs"
)

func TestActionsAreGitOnly(t *testing.T) {
	reg, err := connector.NewRegistry(Actions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range []string{"git.fetch", "git.push"} {
		spec, ok := reg.Spec(a)
		if !ok || !spec.Available(audit.InterfaceGit) || spec.Available(audit.InterfaceMCP) {
			t.Errorf("%s: offered on the wrong interfaces: %+v", a, spec.Interfaces)
		}
	}
	if _, err := (Actions{}).Mint(ctx, jobsJob()); err == nil {
		t.Error("the git namespace minted a credential")
	}
}

func jobsJob() jobs.Job { return jobs.Job{ID: "job-x", Role: "implementer"} }
