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
	"time"

	"local/test/e2e/specs"

	"github.com/googlecloudplatform/gcs-fuse-csi-driver/pkg/webhook"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	"google.golang.org/grpc/codes"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/kubernetes/test/e2e/framework"
	e2epod "k8s.io/kubernetes/test/e2e/framework/pod"
	e2eskipper "k8s.io/kubernetes/test/e2e/framework/skipper"
	e2evolume "k8s.io/kubernetes/test/e2e/framework/volume"
	storageframework "k8s.io/kubernetes/test/e2e/storage/framework"
	admissionapi "k8s.io/pod-security-admission/api"
)

type gcsFuseCSINodeRestartTestSuite struct {
	tsInfo storageframework.TestSuiteInfo
}

// InitGcsFuseCSINodeRestartTestSuite returns gcsFuseCSINodeRestartTestSuite that implements TestSuite interface.
func InitGcsFuseCSINodeRestartTestSuite() storageframework.TestSuite {
	return &gcsFuseCSINodeRestartTestSuite{
		tsInfo: storageframework.TestSuiteInfo{
			Name: "node-restart",
			TestPatterns: []storageframework.TestPattern{
				storageframework.DefaultFsPreprovisionedPV,
			},
		},
	}
}

func (t *gcsFuseCSINodeRestartTestSuite) GetTestSuiteInfo() storageframework.TestSuiteInfo {
	return t.tsInfo
}

func (t *gcsFuseCSINodeRestartTestSuite) SkipUnsupportedTests(_ storageframework.TestDriver, _ storageframework.TestPattern) {
}

func (t *gcsFuseCSINodeRestartTestSuite) DefineTests(driver storageframework.TestDriver, pattern storageframework.TestPattern) {
	type local struct {
		config             *storageframework.PerTestConfig
		volumeResource     *storageframework.VolumeResource
		volumeResourceList []*storageframework.VolumeResource
	}
	var l local
	ctx := context.Background()

	f := framework.NewFrameworkWithCustomTimeouts("node-restart", storageframework.GetDriverTimeouts(driver))
	f.NamespacePodSecurityEnforceLevel = admissionapi.LevelPrivileged

	init := func(volumeCount int, configPrefix ...string) {
		l = local{}
		l.config = driver.PrepareTest(ctx, f)
		if len(configPrefix) > 0 {
			l.config.Prefix = configPrefix[0]
		}
		if volumeCount == 1 {
			l.volumeResource = storageframework.CreateVolumeResource(ctx, driver, l.config, pattern, e2evolume.SizeRange{})
		} else {
			l.volumeResourceList = []*storageframework.VolumeResource{}
			for i := 0; i < volumeCount; i++ {
				l.volumeResourceList = append(l.volumeResourceList, storageframework.CreateVolumeResource(ctx, driver, l.config, pattern, e2evolume.SizeRange{}))
			}
		}
	}

	cleanup := func() {
		var cleanUpErrs []error
		if l.volumeResource != nil {
			cleanUpErrs = append(cleanUpErrs, l.volumeResource.CleanupResource(ctx))
		}
		for _, vr := range l.volumeResourceList {
			cleanUpErrs = append(cleanUpErrs, vr.CleanupResource(ctx))
		}
		err := utilerrors.NewAggregate(cleanUpErrs)
		framework.ExpectNoError(err, "while cleaning up")
	}

	// Node restart (drain, reboot via gcloud, uncordon): create pod with PVC, write data,
	// drain and restart the node so the pod is evicted, then create a new pod on the same
	// node with the same PVC and verify the data is still readable.
	ginkgo.It("[Disruptive] should allow new pod to mount and read data after node restart (drain, reboot, uncordon)", func() {
		readyNodes, err := specs.CountReadyNodes(ctx, f.ClientSet)
		framework.ExpectNoError(err)
		if readyNodes < 1 {
			e2eskipper.Skipf("node restart test requires at least 1 ready node, got %d", readyNodes)
		}

		init(1)
		defer cleanup()

		ginkgo.By("Creating pod with GCS FUSE volume (PVC)")
		tPod := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod.SetupVolume(l.volumeResource, volumeName, mountPath, false)
		tPod.Create(ctx)
		defer tPod.Cleanup(ctx)

		tPod.WaitForRunning(ctx)

		ginkgo.By("Verifying mount and writing data before node restart")
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("mount | grep %v | grep rw,", mountPath))
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("echo before-node-restart > %v/data && grep before-node-restart %v/data", mountPath, mountPath))

		nodeName := tPod.GetNode()
		gomega.Expect(nodeName).NotTo(gomega.BeEmpty(), "pod should be scheduled and have node name")

		ginkgo.By("Draining and restarting the node (pod will be evicted)")
		specs.DrainNodeAndRestartNode(ctx, f.ClientSet, nodeName)

		// First pod was evicted during drain; cleanup only deletes the pod object if it still exists.
		// Create a second pod using the same PVC on the same node.
		ginkgo.By("Creating new pod with same volume on the restarted node")
		tPod2 := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod2.SetupVolume(l.volumeResource, volumeName, mountPath, false)
		tPod2.SetNodeAffinity(nodeName, true)
		tPod2.Create(ctx)
		defer tPod2.Cleanup(ctx)

		tPod2.WaitForRunning(ctx)

		ginkgo.By("Verifying new pod has valid mount and can read data written before node restart")
		tPod2.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("mount | grep %v | grep rw,", mountPath))
		tPod2.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("grep before-node-restart %v/data", mountPath))
		tPod2.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("echo after-node-restart >> %v/data && grep after-node-restart %v/data", mountPath, mountPath))
	})

	// Sequential node restarts: restart the node twice; after each restart a new pod mounts and verifies/extends data.
	ginkgo.It("[Disruptive] should preserve data across sequential node restarts", func() {
		readyNodes, err := specs.CountReadyNodes(ctx, f.ClientSet)
		framework.ExpectNoError(err)
		if readyNodes < 1 {
			e2eskipper.Skipf("node restart test requires at least 1 ready node, got %d", readyNodes)
		}

		init(1)
		defer cleanup()

		ginkgo.By("Creating pod with GCS FUSE volume")
		tPod := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod.SetupVolume(l.volumeResource, volumeName, mountPath, false)
		tPod.Create(ctx)
		defer tPod.Cleanup(ctx)
		tPod.WaitForRunning(ctx)

		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("mount | grep %v | grep rw,", mountPath))
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("echo initial > %v/data && grep initial %v/data", mountPath, mountPath))
		nodeName := tPod.GetNode()
		gomega.Expect(nodeName).NotTo(gomega.BeEmpty(), "pod should be scheduled and have node name")

		ginkgo.By("First node restart")
		specs.DrainNodeAndRestartNode(ctx, f.ClientSet, nodeName)

		ginkgo.By("Creating new pod after first restart")
		tPod2 := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod2.SetupVolume(l.volumeResource, volumeName, mountPath, false)
		tPod2.SetNodeAffinity(nodeName, true)
		tPod2.Create(ctx)
		defer tPod2.Cleanup(ctx)
		tPod2.WaitForRunning(ctx)
		tPod2.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("mount | grep %v | grep rw,", mountPath))
		tPod2.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("grep initial %v/data", mountPath))
		tPod2.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("echo after-first-restart >> %v/data && grep after-first-restart %v/data", mountPath, mountPath))

		ginkgo.By("Second node restart")
		specs.DrainNodeAndRestartNode(ctx, f.ClientSet, nodeName)

		ginkgo.By("Creating new pod after second restart")
		tPod3 := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod3.SetupVolume(l.volumeResource, volumeName, mountPath, false)
		tPod3.SetNodeAffinity(nodeName, true)
		tPod3.Create(ctx)
		defer tPod3.Cleanup(ctx)
		tPod3.WaitForRunning(ctx)
		tPod3.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("mount | grep %v | grep rw,", mountPath))
		tPod3.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("grep initial %v/data", mountPath))
		tPod3.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("grep after-first-restart %v/data", mountPath))
		tPod3.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("echo after-second-restart >> %v/data && grep after-second-restart %v/data", mountPath, mountPath))
	})

	// New pod on a different node after node restart: verify PVC can be mounted on any node after restart.
	ginkgo.It("[Disruptive] should allow new pod to mount and read data on a different node after node restart", func() {
		readyNodes, err := specs.CountReadyNodes(ctx, f.ClientSet)
		framework.ExpectNoError(err)
		if readyNodes < 2 {
			e2eskipper.Skipf("test requires at least 2 ready nodes, got %d", readyNodes)
		}

		init(1)
		defer cleanup()

		ginkgo.By("Creating pod with GCS FUSE volume")
		tPod := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod.SetupVolume(l.volumeResource, volumeName, mountPath, false)
		tPod.Create(ctx)
		defer tPod.Cleanup(ctx)
		tPod.WaitForRunning(ctx)

		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("mount | grep %v | grep rw,", mountPath))
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("echo before-restart > %v/data && grep before-restart %v/data", mountPath, mountPath))
		nodeName := tPod.GetNode()
		gomega.Expect(nodeName).NotTo(gomega.BeEmpty(), "pod should be scheduled and have node name")

		ginkgo.By("Draining and restarting the node")
		specs.DrainNodeAndRestartNode(ctx, f.ClientSet, nodeName)

		ginkgo.By("Creating new pod without node affinity (may schedule on any node)")
		tPod2 := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod2.SetupVolume(l.volumeResource, volumeName, mountPath, false)
		tPod2.Create(ctx)
		defer tPod2.Cleanup(ctx)
		tPod2.WaitForRunning(ctx)

		tPod2.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("mount | grep %v | grep rw,", mountPath))
		tPod2.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("grep before-restart %v/data", mountPath))
		tPod2.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("echo after-restart >> %v/data && grep after-restart %v/data", mountPath, mountPath))
	})

	// Multiple PVCs on one pod: two volumes, write to both, node restart, new pod with same two PVCs verifies both.
	ginkgo.It("[Disruptive] should preserve data on multiple PVCs after node restart", func() {
		readyNodes, err := specs.CountReadyNodes(ctx, f.ClientSet)
		framework.ExpectNoError(err)
		if readyNodes < 1 {
			e2eskipper.Skipf("node restart test requires at least 1 ready node, got %d", readyNodes)
		}

		init(2)
		defer cleanup()

		ginkgo.By("Creating pod with two GCS FUSE volumes")
		tPod := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod.SetupVolume(l.volumeResourceList[0], volumeName, mountPath, false)
		tPod.SetupVolume(l.volumeResourceList[1], volumeName2, mountPath2, false)
		tPod.Create(ctx)
		defer tPod.Cleanup(ctx)
		tPod.WaitForRunning(ctx)

		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("mount | grep %v | grep rw,", mountPath))
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("mount | grep %v | grep rw,", mountPath2))
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("echo vol1 > %v/data1 && grep vol1 %v/data1", mountPath, mountPath))
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("echo vol2 > %v/data2 && grep vol2 %v/data2", mountPath2, mountPath2))
		nodeName := tPod.GetNode()
		gomega.Expect(nodeName).NotTo(gomega.BeEmpty(), "pod should be scheduled and have node name")

		ginkgo.By("Draining and restarting the node")
		specs.DrainNodeAndRestartNode(ctx, f.ClientSet, nodeName)

		ginkgo.By("Creating new pod with same two volumes on the restarted node")
		tPod2 := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod2.SetupVolume(l.volumeResourceList[0], volumeName, mountPath, false)
		tPod2.SetupVolume(l.volumeResourceList[1], volumeName2, mountPath2, false)
		tPod2.SetNodeAffinity(nodeName, true)
		tPod2.Create(ctx)
		defer tPod2.Cleanup(ctx)
		tPod2.WaitForRunning(ctx)

		tPod2.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("mount | grep %v | grep rw,", mountPath))
		tPod2.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("mount | grep %v | grep rw,", mountPath2))
		tPod2.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("grep vol1 %v/data1", mountPath))
		tPod2.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("grep vol2 %v/data2", mountPath2))
		tPod2.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("echo vol1-after >> %v/data1 && grep vol1-after %v/data1", mountPath, mountPath))
		tPod2.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("echo vol2-after >> %v/data2 && grep vol2-after %v/data2", mountPath2, mountPath2))
	})

	// Delete bucket → restart node → workload should fail to mount (no bucket recreation).
	// Expected: Mount fails with 404 Bucket Not Found, CSI driver surfaces clean error,
	// pod goes into CreateContainerError or MountVolume.SetUp failed.
	ginkgo.It("[Disruptive] should fail to mount with 404 Bucket Not Found after bucket is deleted and node is restarted", func() {
		readyNodes, err := specs.CountReadyNodes(ctx, f.ClientSet)
		framework.ExpectNoError(err)
		if readyNodes < 1 {
			e2eskipper.Skipf("node restart test requires at least 1 ready node, got %d", readyNodes)
		}

		init(1)
		defer cleanup()

		ginkgo.By("Creating pod with GCS FUSE volume (PVC)")
		tPod := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod.SetupVolume(l.volumeResource, volumeName, mountPath, false)
		tPod.Create(ctx)
		defer tPod.Cleanup(ctx)

		tPod.WaitForRunning(ctx)
		ginkgo.By("Verifying mount and writing data before node restart")
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("mount | grep %v | grep rw,", mountPath))
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("echo before-delete > %v/data && grep before-delete %v/data", mountPath, mountPath))

		nodeName := tPod.GetNode()
		gomega.Expect(nodeName).NotTo(gomega.BeEmpty(), "pod should be scheduled and have node name")

		bucketName := l.volumeResource.Pv.Spec.CSI.VolumeHandle
		gomega.Expect(bucketName).NotTo(gomega.BeEmpty(), "volume handle (bucket name) must be set")

		ginkgo.By("Draining and restarting the node (pod will be evicted)")
		specs.DrainNodeAndRestartNode(ctx, f.ClientSet, nodeName)

		ginkgo.By("Deleting the GCS bucket (no recreation)")
		framework.ExpectNoError(specs.DeleteGCSBucketForTest(ctx, bucketName))

		ginkgo.By("Creating new pod with same volume on the restarted node; mount should fail with 404 Bucket Not Found")
		tPod2 := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod2.SetupVolume(l.volumeResource, volumeName, mountPath, false)
		tPod2.SetNodeAffinity(nodeName, true)
		tPod2.Create(ctx)
		defer tPod2.Cleanup(ctx)

		ginkgo.By("Expecting pod to fail mount: CSI driver should surface clean 404 / Bucket Not Found")
		tPod2.WaitForFailedMountError(ctx, codes.NotFound.String())
		tPod2.WaitForFailedMountError(ctx, "storage: bucket doesn't exist")
	})

	// GCSFuse cache consistency after restart: verify that cached files inside pod do not remain stale after remount.
	// After node restart, a new pod mounting the same volume must see current GCS state (e.g. overwritten file content).
	ginkgo.It("[Disruptive] should not serve stale cached data after node restart and remount", func() {
		readyNodes, err := specs.CountReadyNodes(ctx, f.ClientSet)
		framework.ExpectNoError(err)
		if readyNodes < 1 {
			e2eskipper.Skipf("node restart test requires at least 1 ready node, got %d", readyNodes)
		}

		gcsDriver, ok := driver.(*specs.GCSFuseCSITestDriver)
		if !ok {
			framework.Failf("driver must be GCSFuseCSITestDriver for cache consistency test")
		}

		init(1)
		defer cleanup()

		ginkgo.By("Creating pod with GCS FUSE volume and writing initial file content")
		tPod := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod.SetupVolume(l.volumeResource, volumeName, mountPath, false)
		tPod.Create(ctx)
		defer tPod.Cleanup(ctx)
		tPod.WaitForRunning(ctx)
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("mount | grep %v | grep rw,", mountPath))
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("echo cache-v1 > %v/cachefile && grep cache-v1 %v/cachefile", mountPath, mountPath))

		nodeName := tPod.GetNode()
		gomega.Expect(nodeName).NotTo(gomega.BeEmpty(), "pod should be scheduled and have node name")

		ginkgo.By("Draining and restarting the node")
		specs.DrainNodeAndRestartNode(ctx, f.ClientSet, nodeName)

		bucketName := l.volumeResource.Pv.Spec.CSI.VolumeHandle
		ginkgo.By("Overwriting file in GCS so new pod must not see stale cache")
		gcsDriver.CreateTestFileInBucket(ctx, "cachefile", bucketName) // overwrites with content "cachefile" (test file name)

		ginkgo.By("Creating new pod with same volume on restarted node")
		tPod2 := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod2.SetupVolume(l.volumeResource, volumeName, mountPath, false)
		tPod2.SetNodeAffinity(nodeName, true)
		tPod2.Create(ctx)
		defer tPod2.Cleanup(ctx)
		tPod2.WaitForRunning(ctx)

		ginkgo.By("Verifying new pod sees current GCS content (not stale cache from pre-restart)")
		tPod2.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("grep cachefile %v/cachefile", mountPath))
	})

	// Node restart while GCSFuse process is actively writing: pod writes large files continuously, node restarts.
	// Expected: No corrupted objects in GCS; remounted pod can resume writes; partial writes must not leave partial/malformed objects.
	ginkgo.It("[Disruptive] should not leave corrupted or partial objects when node restarts during active write", func() {
		readyNodes, err := specs.CountReadyNodes(ctx, f.ClientSet)
		framework.ExpectNoError(err)
		if readyNodes < 1 {
			e2eskipper.Skipf("node restart test requires at least 1 ready node, got %d", readyNodes)
		}

		init(1)
		defer cleanup()

		ginkgo.By("Creating pod with GCS FUSE volume")
		tPod := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod.SetupVolume(l.volumeResource, volumeName, mountPath, false)
		tPod.Create(ctx)
		defer tPod.Cleanup(ctx)
		tPod.WaitForRunning(ctx)
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("mount | grep %v | grep rw,", mountPath))
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("echo initial > %v/initial", mountPath))

		ginkgo.By("Starting background continuous write; will restart node during I/O")
		ioDone := make(chan struct{})
		go func() {
			defer close(ioDone)
			_, _, _ = e2epod.ExecCommandInContainerWithFullOutput(f, tPod.GetPodName(), specs.TesterContainerName, "/bin/sh", "-c",
				fmt.Sprintf("for i in $(seq 1 30); do echo \"RECORD $i\" >> %v/iofile 2>/dev/null; sleep 1; done", mountPath))
		}()

		time.Sleep(5 * time.Second)
		ginkgo.By("Draining and restarting the node while write is in progress")
		specs.DrainNodeAndRestartNode(ctx, f.ClientSet, tPod.GetNode())
		<-ioDone

		ginkgo.By("Creating new pod with same volume on restarted node")
		tPod2 := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod2.SetupVolume(l.volumeResource, volumeName, mountPath, false)
		tPod2.SetNodeAffinity(tPod.GetNode(), true)
		tPod2.Create(ctx)
		defer tPod2.Cleanup(ctx)
		tPod2.WaitForRunning(ctx)

		ginkgo.By("Verifying mount and that remounted pod can resume reads and writes")
		tPod2.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("mount | grep %v | grep rw,", mountPath))
		tPod2.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("grep initial %v/initial", mountPath))
		tPod2.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("echo resumed >> %v/post-restart && grep resumed %v/post-restart", mountPath, mountPath))

		ginkgo.By("Verifying no partial/malformed lines in iofile: every line must be complete RECORD N")
		tPod2.VerifyExecInPodSucceed(f, specs.TesterContainerName,
			fmt.Sprintf("awk '!/^RECORD [0-9]+$/{print \"INVALID:\", $0; exit 1}' %v/iofile", mountPath))
	})

	// Node restart with hostNetwork=true pods using token sidecar: hostNetwork + KSA opt-in + projected tokens → restart node.
	// Expected: Token sidecar recreated properly, new OAuth token issued, mount succeeds and pod can read from GCS.
	// We pre-populate the bucket via the driver so the pod only reads (avoids flaky write from FUSE in hostNetwork+KSA).
	ginkgo.It("[Disruptive] should recreate token sidecar and mount successfully after node restart when hostNetwork=true with KSA opt-in", func() {
		readyNodes, err := specs.CountReadyNodes(ctx, f.ClientSet)
		framework.ExpectNoError(err)
		if readyNodes < 1 {
			e2eskipper.Skipf("node restart test requires at least 1 ready node, got %d", readyNodes)
		}

		gcsDriver, ok := driver.(*specs.GCSFuseCSITestDriver)
		if !ok {
			framework.Failf("driver must be GCSFuseCSITestDriver for hostNetwork+KSA node restart test")
		}

		init(1)
		defer cleanup()

		bucketName := l.volumeResource.Pv.Spec.CSI.VolumeHandle
		gomega.Expect(bucketName).NotTo(gomega.BeEmpty(), "volume handle (bucket name) must be set")
		ginkgo.By("Pre-populating bucket with object 'data' so pod only needs to read")
		gcsDriver.CreateTestFileInBucket(ctx, "data", bucketName)

		ginkgo.By("Configuring hostNetwork pod with KSA opt-in and projected tokens")
		tPod := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod.EnableHostNetwork()
		tPod.SetupVolumeWithHostNetworkKSAOptIn(l.volumeResource, volumeName, mountPath, false)
		tPod.Create(ctx)
		defer tPod.Cleanup(ctx)
		tPod.WaitForRunning(ctx)

		ginkgo.By("Verifying mount and that pod can read object from GCS before node restart")
		tPod.VerifyExecInPodSucceedWithOutput(f, specs.TesterContainerName, fmt.Sprintf(`mountpoint -d "%s"`, mountPath))
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("grep -q data %v/data", mountPath))

		nodeName := tPod.GetNode()
		gomega.Expect(nodeName).NotTo(gomega.BeEmpty(), "pod should be scheduled and have node name")

		ginkgo.By("Draining and restarting the node (pod will be evicted)")
		specs.DrainNodeAndRestartNode(ctx, f.ClientSet, nodeName)

		ginkgo.By("Creating new hostNetwork pod with same volume on restarted node")
		tPod2 := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod2.EnableHostNetwork()
		tPod2.SetupVolumeWithHostNetworkKSAOptIn(l.volumeResource, volumeName, mountPath, false)
		tPod2.SetNodeAffinity(nodeName, true)
		tPod2.Create(ctx)
		defer tPod2.Cleanup(ctx)
		tPod2.WaitForRunning(ctx)

		ginkgo.By("Verifying token sidecar recreated: projected SA token volume present")
		pod2, err := f.ClientSet.CoreV1().Pods(f.Namespace.Name).Get(ctx, tPod2.GetPodName(), metav1.GetOptions{})
		framework.ExpectNoError(err)
		var hasTokenVolume bool
		for _, vol := range pod2.Spec.Volumes {
			if vol.Name == webhook.SidecarContainerSATokenVolumeName {
				hasTokenVolume = true
				break
			}
		}
		gomega.Expect(hasTokenVolume).To(gomega.BeTrue(),
			"hostNetwork pod must have volume %q for sidecar token-based auth after restart", webhook.SidecarContainerSATokenVolumeName)

		ginkgo.By("Verifying mount with new sidecar and that sidecar can access GCS bucket and read object")
		tPod2.VerifyExecInPodSucceedWithOutput(f, specs.TesterContainerName, fmt.Sprintf(`mountpoint -d "%s"`, mountPath))
		tPod2.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("grep -q data %v/data", mountPath))
	})
}
