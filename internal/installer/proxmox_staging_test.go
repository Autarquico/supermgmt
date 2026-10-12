package installer

import (
	"strings"
	"testing"
)

func TestUpgradeAppliance_StagesTheBinaryInAFreshRootOnlyDirectory(t *testing.T) {
	p := newPVEWrap(t)
	p.mustInstall(t)
	p.opLog = nil
	p.ct.dirs[stageDir] = ctMeta{owner: "supermgmt:supermgmt", mode: "777"} // left (or planted) by somebody else
	p.ct.files[stageDir+"/leftover"] = []byte("planted")
	if err := p.run(p.upgradeOpts(), fastHooks(), false); err != nil {
		t.Fatalf("%v\n%s", err, p.out.String())
	}
	clear := p.opIndex("ct.exec /usr/bin/rm -rf " + stageDir)
	create := p.opIndex("ct.exec /usr/bin/mkdir -m 0700 " + stageDir)
	push := p.opIndex("pve.push " + stagedBinary)
	if clear < 0 || create <= clear || push <= create {
		t.Errorf("the directory must be cleared, created private, then used: clear %d, create %d, push %d\n%v", clear, create, push, p.opLog)
	}
	for _, op := range p.opLog {
		if strings.HasPrefix(op, "pve.push ") && strings.Contains(op, "/tmp/") {
			t.Errorf("staged in a world-writable directory: %s", op)
		}
	}
	if _, left := p.ct.dirs[stageDir]; left || p.ct.files[stageDir+"/leftover"] != nil {
		t.Error("the staging directory stayed in the container")
	}
}

func TestUpgradeAppliance_RefusesAStagingDirectoryThatIsNotPrivate(t *testing.T) {
	p := newPVEWrap(t)
	p.mustInstall(t)
	p.opLog = nil
	p.loosenStageDir = true
	err := p.run(p.upgradeOpts(), fastHooks(), false)
	if exitCodeOf(t, err) != ExitConfiguration || !strings.Contains(err.Error(), "not a private root directory") {
		t.Fatalf("err = %v", err)
	}
	if p.opIndex("pve.push "+stagedBinary) >= 0 {
		t.Error("the binary was pushed into a directory somebody else could write")
	}
}
