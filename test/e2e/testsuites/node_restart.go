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
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/kubernetes/test/e2e/framework"
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
}
