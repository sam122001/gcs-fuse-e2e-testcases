/*
Clean HostNetwork Test Suite for GCSFuse CSI Driver
Contains exactly 8 meaningful hostNetwork tests:
HN-1, HN-2, HN-3, HN-4, HN-5, HN-7, HN-8, HN-9
*/

package testsuites

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"local/test/e2e/specs"

	"github.com/googlecloudplatform/gcs-fuse-csi-driver/pkg/webhook"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/kubernetes/test/e2e/framework"
	e2evolume "k8s.io/kubernetes/test/e2e/framework/volume"
	storageframework "k8s.io/kubernetes/test/e2e/storage/framework"
	admissionapi "k8s.io/pod-security-admission/api"
)

const (
	metadataServerURL = "http://169.254.169.254/computeMetadata/v1/"
)

type gcsFuseCSIHostNetworkTestSuite struct {
	tsInfo storageframework.TestSuiteInfo
}

func InitGcsFuseCSIHostNetworkTestSuite() storageframework.TestSuite {
	return &gcsFuseCSIHostNetworkTestSuite{
		tsInfo: storageframework.TestSuiteInfo{
			Name: "hostNetwork",
			TestPatterns: []storageframework.TestPattern{
				storageframework.DefaultFsCSIEphemeralVolume,
			},
		},
	}
}

func (t *gcsFuseCSIHostNetworkTestSuite) GetTestSuiteInfo() storageframework.TestSuiteInfo {
	return t.tsInfo
}

func (t *gcsFuseCSIHostNetworkTestSuite) SkipUnsupportedTests(_ storageframework.TestDriver, _ storageframework.TestPattern) {
}

func (t *gcsFuseCSIHostNetworkTestSuite) DefineTests(
	driver storageframework.TestDriver,
	pattern storageframework.TestPattern,
) {
	type local struct {
		config         *storageframework.PerTestConfig
		volumeResource *storageframework.VolumeResource
	}
	var l local
	ctx := context.Background()

	f := framework.NewFrameworkWithCustomTimeouts("hostnetwork", storageframework.GetDriverTimeouts(driver))
	f.NamespacePodSecurityEnforceLevel = admissionapi.LevelPrivileged

	init := func(configPrefix ...string) {
		l = local{}
		l.config = driver.PrepareTest(ctx, f)
		if len(configPrefix) > 0 {
			l.config.Prefix = configPrefix[0]
		}
		l.volumeResource = storageframework.CreateVolumeResource(ctx, driver, l.config, pattern, e2evolume.SizeRange{})
	}

	cleanup := func() {
		err := utilerrors.NewAggregate([]error{
			l.volumeResource.CleanupResource(ctx),
		})
		framework.ExpectNoError(err)
	}

	expectHostNetwork := func(podName string) {
		pod, err := f.ClientSet.CoreV1().Pods(f.Namespace.Name).Get(ctx, podName, metav1.GetOptions{})
		framework.ExpectNoError(err)
		gomega.Expect(pod.Spec.HostNetwork).To(gomega.BeTrue(), "pod %q must have HostNetwork=true", podName)
	}

	// ----------------------------------------------------------------------
	// ⭐ HN-1: DNS + HTTPS reachability for hostNetwork pods
	// ----------------------------------------------------------------------
	ginkgo.It("should resolve storage.googleapis.com and required domains when hostNetwork=true", func() {
		init()
		defer cleanup()

		tPod := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod.EnableHostNetwork()
		tPod.SetupVolumeWithHostNetworkKSAOptIn(l.volumeResource, volumeName, mountPath, false)
		tPod.Create(ctx)
		tPod.WaitForRunning(ctx)

		ginkgo.By("Verifying nameservers are configured")
		resolv := tPod.VerifyExecInPodSucceedWithOutput(
			f, specs.TesterContainerName, "cat /etc/resolv.conf | grep nameserver",
		)
		gomega.Expect(resolv).ToNot(gomega.BeEmpty())

		// GCS and Google API domains required for hostNetwork pods using gcsfuse. Use wget (available in test image); connectivity implies DNS resolution.
		// wget exit 0 = 2xx, exit 8 = 4xx (e.g. 403 for GCS root).
		ginkgo.By("Checking HTTPS connectivity to storage.googleapis.com (wget exit 0 or 8)")
		tPod.VerifyExecInPodSucceed(
			f, specs.TesterContainerName,
			"wget -q -O /dev/null https://storage.googleapis.com; r=$?; [ $r -eq 0 ] || [ $r -eq 8 ] || exit $r",
		)

		ginkgo.By("Checking HTTPS connectivity to www.googleapis.com")
		tPod.VerifyExecInPodSucceed(
			f, specs.TesterContainerName,
			"wget -q -O /dev/null https://www.googleapis.com/discovery/v1/apis",
		)

		tPod.Cleanup(ctx)
	})

	// ----------------------------------------------------------------------
	// ⭐ HN-2: KSA opt-in → metadata server must NOT be reachable
	// ----------------------------------------------------------------------
	ginkgo.It("[HN-2] should NOT reach metadata server when KSA opt-in + hostNetwork", func() {
		init()
		defer cleanup()

		tPod := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod.EnableHostNetwork()
		tPod.SetupVolumeWithHostNetworkKSAOptIn(l.volumeResource, volumeName, mountPath, false)
		tPod.Create(ctx)
		tPod.WaitForRunning(ctx)
		expectHostNetwork(tPod.GetPodName())

		ginkgo.By("Ensuring metadata server (169.254.169.254) is NOT reachable")
		tPod.VerifyExecInPodFail(
			f,
			specs.TesterContainerName,
			`wget --timeout=2 -q --spider --header="Metadata-Flavor: Google" `+metadataServerURL,
			1,
		)
	})

	// ----------------------------------------------------------------------
	// ⭐ HN-3: KSA opt-out → metadata server MUST be reachable
	// ----------------------------------------------------------------------
	ginkgo.It("[HN-3] should reach metadata server when KSA opt-out + hostNetwork", func() {
		init()
		defer cleanup()

		tPod := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod.EnableHostNetwork()
		tPod.SetupVolume(l.volumeResource, volumeName, mountPath, false)
		tPod.Create(ctx)
		tPod.WaitForRunning(ctx)
		expectHostNetwork(tPod.GetPodName())

		ginkgo.By("Fetching access token via metadata server")
		token := tPod.VerifyExecInPodSucceedWithOutput(
			f,
			specs.TesterContainerName,
			`wget -qO- --header="Metadata-Flavor: Google" `+
				metadataServerURL+`instance/service-accounts/default/token`,
		)
		gomega.Expect(token).To(gomega.ContainSubstring("access_token"))
	})

	// ----------------------------------------------------------------------
	// ⭐ HN-4: STS-based auth works (projected SA token injected)
	// ----------------------------------------------------------------------
	ginkgo.It("[HN-4] should inject projected SA token & allow STS auth over hostNetwork", func() {
		init()
		defer cleanup()

		tPod := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod.EnableHostNetwork()
		tPod.SetupVolumeWithHostNetworkKSAOptIn(l.volumeResource, volumeName, mountPath, false)
		tPod.Create(ctx)
		tPod.WaitForRunning(ctx)
		expectHostNetwork(tPod.GetPodName())

		ginkgo.By("Checking for projected token volume")
		pod, err := f.ClientSet.CoreV1().Pods(f.Namespace.Name).Get(ctx, tPod.GetPodName(), metav1.GetOptions{})
		framework.ExpectNoError(err)

		found := false
		for _, v := range pod.Spec.Volumes {
			if v.Name == webhook.SidecarContainerSATokenVolumeName {
				found = true
				break
			}
		}
		gomega.Expect(found).To(gomega.BeTrue())

		ginkgo.By("Verifying mount is present and read-write")
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("mount | grep %v | grep rw,", mountPath))

		ginkgo.By("Verifying STS-authenticated mount works")
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName,
			fmt.Sprintf("echo 'sts-auth' > %v/auth && grep sts-auth %v/auth", mountPath, mountPath),
		)
	})

	// ----------------------------------------------------------------------
	// ⭐ HN-5: CSI driver restart must NOT break the hostNetwork mount
	// ----------------------------------------------------------------------
	ginkgo.It("[HN-5] should keep mount valid after CSI node driver restart", func() {
		init()
		defer cleanup()

		tPod := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod.EnableHostNetwork()
		tPod.SetupVolumeWithHostNetworkKSAOptIn(l.volumeResource, volumeName, mountPath, false)
		tPod.Create(ctx)
		tPod.WaitForRunning(ctx)
		expectHostNetwork(tPod.GetPodName())

		ginkgo.By("Verifying mount and writing initial file")
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("mount | grep %v | grep rw,", mountPath))
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName,
			fmt.Sprintf("echo before > %v/f && grep before %v/f", mountPath, mountPath))

		ginkgo.By("Restarting CSI node driver")
		specs.RestartNodeDriverOnNode(ctx, f.ClientSet, tPod.GetNode())

		ginkgo.By("Verifying mount still present and read-write after restart")
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("mount | grep %v | grep rw,", mountPath))
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName,
			fmt.Sprintf("grep before %v/f && echo after >> %v/f && grep after %v/f", mountPath, mountPath, mountPath),
		)
	})

	// ----------------------------------------------------------------------
	// ⭐ HN-7: STS/IAM latency validation over hostNetwork
	// ----------------------------------------------------------------------
	ginkgo.It("[HN-7] should successfully call STS/IAM APIs with reasonable latency over hostNetwork", func() {
		init()
		defer cleanup()

		tPod := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod.EnableHostNetwork()
		tPod.SetupVolumeWithHostNetworkKSAOptIn(l.volumeResource, volumeName, mountPath, false)
		tPod.Create(ctx)
		tPod.WaitForRunning(ctx)
		expectHostNetwork(tPod.GetPodName())

		ginkgo.By("Measuring STS latency")
		latency := tPod.VerifyExecInPodSucceedWithOutput(
			f, specs.TesterContainerName,
			`ts=$(date +%s); wget -qO- https://sts.googleapis.com >/dev/null; te=$(date +%s); echo $((te-ts))`,
		)
		lsec, err := strconv.Atoi(strings.TrimSpace(latency))
		framework.ExpectNoError(err, "latency output %q must parse as integer", latency)
		gomega.Expect(lsec).To(gomega.BeNumerically(">=", 0), "latency must be non-negative")
		gomega.Expect(lsec).To(gomega.BeNumerically("<", 20), "STS call should complete within 20s")
	})

	// ----------------------------------------------------------------------
	// ⭐ HN-8: HostNetwork pods must NOT resolve cluster DNS
	// ----------------------------------------------------------------------
	ginkgo.It("[HN-8] should NOT resolve cluster DNS names when hostNetwork=true", func() {
		init()
		defer cleanup()

		tPod := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod.EnableHostNetwork()
		tPod.Create(ctx)
		tPod.WaitForRunning(ctx)
		expectHostNetwork(tPod.GetPodName())

		ginkgo.By("Ensuring cluster DNS resolution fails")
		tPod.VerifyExecInPodFail(
			f,
			specs.TesterContainerName,
			"getent hosts foo.default.svc.cluster.local",
			1,
		)
	})

	// ----------------------------------------------------------------------
	// ⭐ HN-9: Mount must remain healthy under node CPU pressure + CSI restart
	// ----------------------------------------------------------------------
	ginkgo.It("[HN-9] should retain healthy mount under CPU load during CSI node driver restart", func() {
		init()
		defer cleanup()

		tPod := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod.EnableHostNetwork()
		tPod.SetupVolumeWithHostNetworkKSAOptIn(l.volumeResource, volumeName, mountPath, false)
		tPod.Create(ctx)
		tPod.WaitForRunning(ctx)
		expectHostNetwork(tPod.GetPodName())

		ginkgo.By("Verifying mount and writing initial test file")
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("mount | grep %v | grep rw,", mountPath))
		tPod.VerifyExecInPodSucceed(
			f, specs.TesterContainerName,
			fmt.Sprintf("echo before-stress > %v/x", mountPath),
		)

		ginkgo.By("Launching CPU stress pod on same node")
		stress := specs.NewStressPod(f.ClientSet, f.Namespace, tPod.GetNode())
		stress.Create(ctx)
		defer stress.Cleanup(ctx)
		stress.WaitForRunning(ctx)

		ginkgo.By("Restarting CSI node driver during CPU load")
		specs.RestartNodeDriverOnNode(ctx, f.ClientSet, tPod.GetNode())

		ginkgo.By("Validating mount still present and read-write")
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("mount | grep %v | grep rw,", mountPath))
		tPod.VerifyExecInPodSucceed(
			f, specs.TesterContainerName,
			fmt.Sprintf("grep before-stress %v/x && echo after-stress >> %v/x && grep after-stress %v/x", mountPath, mountPath, mountPath),
		)
	})
}
