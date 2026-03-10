/*
Clean HostNetwork Test Suite for GCSFuse CSI Driver
Contains exactly 7 meaningful hostNetwork tests:
HN-1, HN-2, HN-3, HN-4, HN-5, HN-8, HN-9
*/

package testsuites

import (
	"context"
	"fmt"
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
	// ⭐ HN-1: Verify hostNetwork pod uses node network and can reach GCS APIs
	// ----------------------------------------------------------------------
	ginkgo.It("[HN-1] should use node network to reach internet and Google APIs", func() {
		init()
		defer cleanup()

		tPod := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod.EnableHostNetwork()
		tPod.SetupVolumeWithHostNetworkKSAOptIn(l.volumeResource, volumeName, mountPath, false)

		ginkgo.By("Creating hostNetwork pod")
		tPod.Create(ctx)
		tPod.WaitForRunning(ctx)

		ginkgo.By("Fetching pod object")
		pod, err := f.ClientSet.CoreV1().Pods(f.Namespace.Name).Get(ctx, tPod.GetPodName(), metav1.GetOptions{})
		framework.ExpectNoError(err)

		ginkgo.By("Fetching node object")
		node, err := f.ClientSet.CoreV1().Nodes().Get(ctx, pod.Spec.NodeName, metav1.GetOptions{})
		framework.ExpectNoError(err)

		ginkgo.By("Extracting node internal IP")
		var nodeIP string
		for _, addr := range node.Status.Addresses {
			if addr.Type == "InternalIP" {
				nodeIP = addr.Address
				break
			}
		}
		framework.ExpectNoError(err)
		gomega.Expect(nodeIP).ToNot(gomega.BeEmpty(), "node internal IP must exist")

		ginkgo.By("Verifying pod shares node network namespace (PodIP == NodeIP)")
		gomega.Expect(pod.Status.PodIP).To(gomega.Equal(nodeIP),
			fmt.Sprintf("expected pod IP %s to equal node IP %s", pod.Status.PodIP, nodeIP),
		)

		ginkgo.By("Verifying default route exists in node's route table via /proc/net/route")
		tPod.VerifyExecInPodSucceed(
			f,
			specs.TesterContainerName,
			"cat /proc/net/route | grep -w '00000000'",
		)

		ginkgo.By("Checking DNS configuration inside the pod")
		resolvConf := tPod.VerifyExecInPodSucceedWithOutput(
			f,
			specs.TesterContainerName,
			"cat /etc/resolv.conf",
		)
		gomega.Expect(resolvConf).To(gomega.ContainSubstring("nameserver"))

		ginkgo.By("Checking outbound internet connectivity (public IP detection)")
		publicIP := tPod.VerifyExecInPodSucceedWithOutput(
			f,
			specs.TesterContainerName,
			"wget -qO- https://api.ipify.org",
		)

		framework.Logf("Public IP seen from hostNetwork pod: %s", publicIP)
		gomega.Expect(strings.TrimSpace(publicIP)).ToNot(gomega.BeEmpty())

		ginkgo.By("Checking connectivity to storage.googleapis.com (allow 403)")
		tPod.VerifyExecInPodSucceed(
			f,
			specs.TesterContainerName,
			"wget -q -O /dev/null https://storage.googleapis.com; r=$?; [ $r -eq 0 ] || [ $r -eq 8 ] || exit $r",
		)

		ginkgo.By("Checking connectivity to Google APIs")
		tPod.VerifyExecInPodSucceed(
			f,
			specs.TesterContainerName,
			"wget -q -O /dev/null https://www.googleapis.com/discovery/v1/apis",
		)

		ginkgo.By("Cleaning up test pod")
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
			`wget --timeout=5m -q --spider --header="Metadata-Flavor: Google" `+metadataServerURL,
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
	// ⭐ HN-6: DNS resolution works using node DNS
	// ----------------------------------------------------------------------
	ginkgo.It("[HN-6] should resolve DNS using node DNS configuration over hostNetwork", func() {
		init()
		defer cleanup()

		tPod := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod.EnableHostNetwork()
		tPod.SetupVolumeWithHostNetworkKSAOptIn(l.volumeResource, volumeName, mountPath, false)
		tPod.Create(ctx)
		tPod.WaitForRunning(ctx)
		expectHostNetwork(tPod.GetPodName())

		ginkgo.By("Checking DNS configuration inside the pod")
		resolvConf := tPod.VerifyExecInPodSucceedWithOutput(
			f,
			specs.TesterContainerName,
			"cat /etc/resolv.conf",
		)
		gomega.Expect(resolvConf).To(gomega.ContainSubstring("nameserver"))

		ginkgo.By("Resolving and connecting to an external hostname")
		tPod.VerifyExecInPodSucceed(
			f,
			specs.TesterContainerName,
			"wget -q -O /dev/null https://www.google.com",
		)
	})

	// ----------------------------------------------------------------------
	// ⭐ HN-7: HostNetwork pod uses node network interface
	// ----------------------------------------------------------------------
	ginkgo.It("[HN-7] should expose node IP on a network interface when hostNetwork=true", func() {
		init()
		defer cleanup()

		tPod := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod.EnableHostNetwork()
		tPod.SetupVolumeWithHostNetworkKSAOptIn(l.volumeResource, volumeName, mountPath, false)
		tPod.Create(ctx)
		tPod.WaitForRunning(ctx)
		expectHostNetwork(tPod.GetPodName())

		ginkgo.By("Fetching pod object")
		pod, err := f.ClientSet.CoreV1().Pods(f.Namespace.Name).Get(ctx, tPod.GetPodName(), metav1.GetOptions{})
		framework.ExpectNoError(err)

		ginkgo.By("Verifying pod IP is present in kernel FIB (host network namespace)")
		checkCmd := fmt.Sprintf("cat /proc/net/fib_trie | grep -w '%s'", pod.Status.PodIP)
		tPod.VerifyExecInPodSucceed(
			f,
			specs.TesterContainerName,
			checkCmd,
		)
	})

}
