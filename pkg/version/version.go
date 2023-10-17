package version

import (
	"fmt"
	"os"
	"runtime"

	"github.com/hashicorp/go-version"
	"k8s.io/klog/v2"
)

type versionMessage struct {
	minVersionInclusive string
	maxVersionExclusive string
	message             string
}

// Version and BuildDate are injected at build time via ldflags
var (
	BuildDate string
	Version   string

	msgVersionArr = []versionMessage{
		{
			minVersionInclusive: "v2.0.0",
			maxVersionExclusive: "v2.1.0",
			message: "Version v2.X introduces backward compatibility breaking changes, the kube-router project " +
				"recommends that you read the release notes carefully before deploying: " +
				"https://github.com/cloudnativelabs/kube-router/releases/tag/v2.0.0",
		},
	}
)

func (ver versionMessage) versionApplicable(testVerStr string) bool {
	minVer, err1 := version.NewVersion(ver.minVersionInclusive)
	maxVer, err2 := version.NewVersion(ver.maxVersionExclusive)
	testVer, err3 := version.NewVersion(testVerStr)

	// When in doubt return false
	if err1 != nil || err2 != nil || err3 != nil {
		klog.Warningf("encountered an error while trying to parse version numbers: %v - %v - %v", err1, err2, err3)
		return false
	}

	return testVer.GreaterThanOrEqual(minVer) && testVer.LessThan(maxVer)
}

func PrintVersion(logOutput bool) {
	output := fmt.Sprintf("Running %v version %s, built on %s, %s\n", os.Args[0], Version, BuildDate, runtime.Version())

	outputToStream(output, logOutput)
}

func PrintVersionMessages(logOutput bool) {
	for _, verMsg := range msgVersionArr {
		if verMsg.versionApplicable(Version) {
			outputToStream(verMsg.message, logOutput)
		}
	}
}

func outputToStream(output string, logOutput bool) {
	if !logOutput {
		_, _ = fmt.Fprintf(os.Stderr, "%s", output)
	} else {
		klog.Info(output)
	}
}
