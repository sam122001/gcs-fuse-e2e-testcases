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
				storageframework.DefaultFsDynamicPV,
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
		config         *storageframework.PerTestConfig
		volumeResource *storageframework.VolumeResource
	}
	var l local
	ctx := context.Background()

	f := framework.NewFrameworkWithCustomTimeouts("node-restart", storageframework.GetDriverTimeouts(driver))
	f.NamespacePodSecurityEnforceLevel = admissionapi.LevelPrivileged

	init := func() {
		l = local{}
		l.config = driver.PrepareTest(ctx, f)
		l.volumeResource = storageframework.CreateVolumeResource(ctx, driver, l.config, pattern, e2evolume.SizeRange{})
	}

	cleanup := func() {
		var cleanUpErrs []error
		if l.volumeResource != nil {
			cleanUpErrs = append(cleanUpErrs, l.volumeResource.CleanupResource(ctx))
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

		init()
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
}
