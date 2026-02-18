/*
Copyright 2018 The Kubernetes Authors.
Copyright 2022 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package testsuites

import (
	"context"
	"fmt"

	"local/test/e2e/specs"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/kubernetes/test/e2e/framework"
	e2evolume "k8s.io/kubernetes/test/e2e/framework/volume"
	storageframework "k8s.io/kubernetes/test/e2e/storage/framework"
	admissionapi "k8s.io/pod-security-admission/api"
)

type gcsFuseCSIHostNetworkTestSuite struct {
	tsInfo storageframework.TestSuiteInfo
}

// InitGcsFuseCSIHostNetworkTestSuite returns gcsFuseCSIHostNetworkTestSuite that implements TestSuite interface.
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

func (t *gcsFuseCSIHostNetworkTestSuite) DefineTests(driver storageframework.TestDriver, pattern storageframework.TestPattern) {
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
		var cleanUpErrs []error
		cleanUpErrs = append(cleanUpErrs, l.volumeResource.CleanupResource(ctx))
		err := utilerrors.NewAggregate(cleanUpErrs)
		framework.ExpectNoError(err, "while cleaning up")
	}

	// Test 1: HostNetwork pod with KSA opt-in should mount GCS bucket and read/write data.
	ginkgo.It("should mount GCS bucket and read/write data when hostNetwork=true with KSA opt-in", func() {
		init()
		defer cleanup()

		ginkgo.By("Configuring hostNetwork pod with KSA opt-in")
		tPod := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod.EnableHostNetwork()
		tPod.SetupVolumeWithHostNetworkKSAOptIn(l.volumeResource, volumeName, mountPath, false)

		ginkgo.By("Deploying hostNetwork pod")
		tPod.Create(ctx)

		ginkgo.By("Checking pod is running")
		tPod.WaitForRunning(ctx)

		ginkgo.By("Verifying mount is present")
		tPod.VerifyExecInPodSucceedWithOutput(f, specs.TesterContainerName, fmt.Sprintf(`mountpoint -d "%s"`, mountPath))

		ginkgo.By("Verifying read/write to bucket")
		testFile := "hostnetwork-data-test"
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("touch %v/%v", mountPath, testFile))
		contents := tPod.VerifyExecInPodSucceedWithOutput(f, specs.TesterContainerName, fmt.Sprintf("ls %v", mountPath))
		gomega.Expect(contents).To(gomega.Equal(testFile))

		ginkgo.By("Deleting pod")
		tPod.Cleanup(ctx)
	})

	// Test 2: HostNetwork pod with multiple GCS volumes (KSA opt-in) should mount and access both.
	ginkgo.It("should mount and access multiple GCS volumes when hostNetwork=true with KSA opt-in", func() {
		init()
		defer cleanup()

		ginkgo.By("Configuring hostNetwork pod with two volumes and KSA opt-in")
		tPod := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod.EnableHostNetwork()
		tPod.SetupVolumeWithHostNetworkKSAOptIn(l.volumeResource, volumeName, mountPath, false)
		tPod.SetupVolumeWithHostNetworkKSAOptIn(l.volumeResource, volumeName2, mountPath2, false)

		ginkgo.By("Deploying hostNetwork pod")
		tPod.Create(ctx)

		ginkgo.By("Checking pod is running")
		tPod.WaitForRunning(ctx)

		ginkgo.By("Verifying both mounts are present")
		tPod.VerifyExecInPodSucceedWithOutput(f, specs.TesterContainerName, fmt.Sprintf(`mountpoint -d "%s"`, mountPath))
		tPod.VerifyExecInPodSucceedWithOutput(f, specs.TesterContainerName, fmt.Sprintf(`mountpoint -d "%s"`, mountPath2))

		ginkgo.By("Verifying read/write to both volumes")
		testFile := "multi-volume-test"
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("touch %v/%v", mountPath, testFile))
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("touch %v/%v", mountPath2, testFile))
		contents1 := tPod.VerifyExecInPodSucceedWithOutput(f, specs.TesterContainerName, fmt.Sprintf("ls %v", mountPath))
		contents2 := tPod.VerifyExecInPodSucceedWithOutput(f, specs.TesterContainerName, fmt.Sprintf("ls %v", mountPath2))
		gomega.Expect(contents1).To(gomega.Equal(testFile))
		gomega.Expect(contents2).To(gomega.Equal(testFile))

		ginkgo.By("Deleting pod")
		tPod.Cleanup(ctx)
	})

	// Test 3: Pod spec must have hostNetwork=true when running (verify via API).
	ginkgo.It("should run with hostNetwork=true in pod spec", func() {
		init()
		defer cleanup()

		ginkgo.By("Configuring hostNetwork pod with KSA opt-in")
		tPod := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod.EnableHostNetwork()
		tPod.SetupVolumeWithHostNetworkKSAOptIn(l.volumeResource, volumeName, mountPath, false)

		ginkgo.By("Deploying hostNetwork pod")
		tPod.Create(ctx)

		ginkgo.By("Checking pod is running")
		tPod.WaitForRunning(ctx)

		ginkgo.By("Verifying pod has HostNetwork=true via API")
		pod, err := f.ClientSet.CoreV1().Pods(f.Namespace.Name).Get(ctx, tPod.GetPodName(), metav1.GetOptions{})
		framework.ExpectNoError(err)
		gomega.Expect(pod.Spec.HostNetwork).To(gomega.BeTrue(), "pod spec must have hostNetwork=true for hostNetwork tests")

		ginkgo.By("Verifying mounted volume is accessible")
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("mount | grep %v | grep rw,", mountPath))

		ginkgo.By("Deleting pod")
		tPod.Cleanup(ctx)
	})

	// Test 4: Writing to a read-only volume on a hostNetwork pod with KSA opt-in should fail.
	ginkgo.It("should fail when writing to read-only volume on hostnetwork pod with KSA opt-in", func() {
		init()
		defer cleanup()

		ginkgo.By("Configuring hostNetwork pod with read-only volume and KSA opt-in")
		tPod := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod.EnableHostNetwork()
		tPod.SetupVolumeWithHostNetworkKSAOptIn(l.volumeResource, volumeName, mountPath, true) // true = readOnly

		ginkgo.By("Deploying hostNetwork pod")
		tPod.Create(ctx)

		ginkgo.By("Checking pod is running")
		tPod.WaitForRunning(ctx)

		ginkgo.By("Verifying volume is mounted read-only")
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("mount | grep %v | grep ro,", mountPath))

		ginkgo.By("Expecting error when writing to read-only volume")
		tPod.VerifyExecInPodFail(f, specs.TesterContainerName, fmt.Sprintf("echo 'hello world' > %v/data", mountPath), 1)

		ginkgo.By("Deleting pod")
		tPod.Cleanup(ctx)
	})

	// Test 5: HostNetwork pod with KSA opt-in and automountServiceAccountToken=false should run and access volume.
	ginkgo.It("should run hostnetwork pod with KSA opt-in and automountServiceAccountToken false", func() {
		init()
		defer cleanup()

		ginkgo.By("Configuring hostNetwork pod with KSA opt-in and automountServiceAccountToken=false")
		tPod := specs.NewTestPodModifiedSpec(f.ClientSet, f.Namespace, false)
		tPod.EnableHostNetwork()
		tPod.SetupVolumeWithHostNetworkKSAOptIn(l.volumeResource, volumeName, mountPath, false)

		ginkgo.By("Deploying hostNetwork pod")
		tPod.Create(ctx)

		ginkgo.By("Checking pod is running")
		tPod.WaitForRunning(ctx)

		ginkgo.By("Verifying pod has AutomountServiceAccountToken=false via API")
		pod, err := f.ClientSet.CoreV1().Pods(f.Namespace.Name).Get(ctx, tPod.GetPodName(), metav1.GetOptions{})
		framework.ExpectNoError(err)
		gomega.Expect(pod.Spec.AutomountServiceAccountToken).ToNot(gomega.BeNil())
		gomega.Expect(*pod.Spec.AutomountServiceAccountToken).To(gomega.BeFalse())

		ginkgo.By("Verifying mount is present and volume is accessible")
		tPod.VerifyExecInPodSucceedWithOutput(f, specs.TesterContainerName, fmt.Sprintf(`mountpoint -d "%s"`, mountPath))
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("echo 'hello world' > %v/data && grep 'hello world' %v/data", mountPath, mountPath))

		ginkgo.By("Deleting pod")
		tPod.Cleanup(ctx)
	})

	// Test 6: Dedicated gcsfuse-on-hostNetwork test: assert FUSE mount type and gcsfuse-specific behavior (implicit dirs).
	ginkgo.It("should mount GCS bucket via gcsfuse when hostNetwork=true with KSA opt-in and expose fuse mount with implicit-dirs", func() {
		init(specs.ImplicitDirsVolumePrefix)
		defer cleanup()

		ginkgo.By("Configuring hostNetwork pod with KSA opt-in and implicit-dirs volume")
		tPod := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod.EnableHostNetwork()
		tPod.SetupVolumeWithHostNetworkKSAOptIn(l.volumeResource, volumeName, mountPath, false)

		ginkgo.By("Deploying hostNetwork pod")
		tPod.Create(ctx)

		ginkgo.By("Checking pod is running")
		tPod.WaitForRunning(ctx)

		ginkgo.By("Verifying mount is present")
		tPod.VerifyExecInPodSucceedWithOutput(f, specs.TesterContainerName, fmt.Sprintf(`mountpoint -d "%s"`, mountPath))

		ginkgo.By("Verifying mount is fuse/gcsfuse (not just any volume)")
		mountLine := tPod.VerifyExecInPodSucceedWithOutput(f, specs.TesterContainerName, fmt.Sprintf("mount | grep '%s'", mountPath))
		gomega.Expect(mountLine).To(gomega.Not(gomega.BeEmpty()), "mount table should contain entry for %s", mountPath)
		gomega.Expect(mountLine).To(gomega.MatchRegexp(`fuse|gcsfuse`), "mount at %s should be a fuse/gcsfuse mount, got: %s", mountPath, mountLine)

		ginkgo.By("Verifying gcsfuse-specific behavior: read/write in implicit directory")
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName,
			fmt.Sprintf("echo 'hello world' > %v/%v/data && grep 'hello world' %v/%v/data", mountPath, specs.ImplicitDirsPath, mountPath, specs.ImplicitDirsPath))

		ginkgo.By("Deleting pod")
		tPod.Cleanup(ctx)
	})
	// Test 7: HostNetwork pod should access metadata server and fetch token successfully.
	ginkgo.It("should access metadata server and fetch token when hostNetwork=true with KSA opt-in", func() {
		init()
		defer cleanup()

		ginkgo.By("Configuring hostNetwork pod with KSA opt-in")
		tPod := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod.EnableHostNetwork()
		tPod.SetupVolumeWithHostNetworkKSAOptIn(l.volumeResource, volumeName, mountPath, false)

		ginkgo.By("Deploying hostNetwork pod")
		tPod.Create(ctx)

		ginkgo.By("Waiting for pod to be running")
		tPod.WaitForRunning(ctx)

		// Use a valid metadata path; root URL often returns 400. 169.254.169.254 is the standard GCE link-local address.
		ginkgo.By("Verifying metadata server is reachable")
		tPod.VerifyExecInPodSucceed(
			f,
			specs.TesterContainerName,
			`wget -q -O - --header="Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/instance/`,
		)

		ginkgo.By("Fetching access token from metadata server")
		tokenOutput := tPod.VerifyExecInPodSucceedWithOutput(
			f,
			specs.TesterContainerName,
			`wget -q -O - --header="Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token`,
		)

		gomega.Expect(tokenOutput).To(
			gomega.ContainSubstring("access_token"),
			"metadata server should return access_token",
		)

		ginkgo.By("Verifying GCS Fuse mount works after metadata access")
		tPod.VerifyExecInPodSucceedWithOutput(
			f,
			specs.TesterContainerName,
			fmt.Sprintf(`mountpoint -d "%s"`, mountPath),
		)

		ginkgo.By("Writing file to confirm token-based access works")
		tPod.VerifyExecInPodSucceed(
			f,
			specs.TesterContainerName,
			fmt.Sprintf("echo 'metadata-test' > %s/metadata-check && grep 'metadata-test' %s/metadata-check",
				mountPath, mountPath),
		)

		ginkgo.By("Deleting pod")
		tPod.Cleanup(ctx)
	})

	// Test 8: DNS/HTTPS to storage.googleapis.com must work in hostNetwork pod (same volume resource, single pod).
	ginkgo.It("should resolve and reach storage.googleapis.com when hostNetwork=true with KSA opt-in", func() {
		init()
		defer cleanup()

		ginkgo.By("Configuring hostNetwork pod with KSA opt-in")
		tPod := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod.EnableHostNetwork()
		tPod.SetupVolumeWithHostNetworkKSAOptIn(l.volumeResource, volumeName, mountPath, false)

		ginkgo.By("Deploying hostNetwork pod")
		tPod.Create(ctx)

		ginkgo.By("Checking pod is running")
		tPod.WaitForRunning(ctx)

		ginkgo.By("Verifying DNS resolution for storage.googleapis.com")
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName,
			"getent hosts storage.googleapis.com || nslookup storage.googleapis.com")

		ginkgo.By("Verifying HTTPS reachability to storage.googleapis.com")
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName,
			"wget -q --spider --timeout=10 https://storage.googleapis.com")

		ginkgo.By("Verifying mount and read/write (GCS API over network)")
		tPod.VerifyExecInPodSucceedWithOutput(f, specs.TesterContainerName, fmt.Sprintf(`mountpoint -d "%s"`, mountPath))
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("echo dns-https-ok > %v/dns-https-test && cat %v/dns-https-test", mountPath, mountPath))

		ginkgo.By("Deleting pod")
		tPod.Cleanup(ctx)
	})

}
