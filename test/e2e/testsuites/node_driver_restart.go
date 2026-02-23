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
	"os"
	"strconv"
	"time"

	"local/test/e2e/specs"
	"local/test/e2e/utils"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/klog/v2"
	"k8s.io/kubernetes/test/e2e/framework"
	e2epod "k8s.io/kubernetes/test/e2e/framework/pod"
	e2evolume "k8s.io/kubernetes/test/e2e/framework/volume"
	storageframework "k8s.io/kubernetes/test/e2e/storage/framework"
	admissionapi "k8s.io/pod-security-admission/api"
)

type gcsFuseCSINodeDriverRestartTestSuite struct {
	tsInfo storageframework.TestSuiteInfo
}

// InitGcsFuseCSINodeDriverRestartTestSuite returns gcsFuseCSINodeDriverRestartTestSuite that implements TestSuite interface.
func InitGcsFuseCSINodeDriverRestartTestSuite() storageframework.TestSuite {
	return &gcsFuseCSINodeDriverRestartTestSuite{
		tsInfo: storageframework.TestSuiteInfo{
			Name: "node-driver-restart",
			TestPatterns: []storageframework.TestPattern{
				storageframework.DefaultFsCSIEphemeralVolume,
			},
		},
	}
}

func (t *gcsFuseCSINodeDriverRestartTestSuite) GetTestSuiteInfo() storageframework.TestSuiteInfo {
	return t.tsInfo
}

func (t *gcsFuseCSINodeDriverRestartTestSuite) SkipUnsupportedTests(_ storageframework.TestDriver, _ storageframework.TestPattern) {
}

func (t *gcsFuseCSINodeDriverRestartTestSuite) DefineTests(driver storageframework.TestDriver, pattern storageframework.TestPattern) {
	envVar := os.Getenv(utils.TestWithNativeSidecarEnvVar)
	supportsNativeSidecar, err := strconv.ParseBool(envVar)
	if err != nil {
		klog.Fatalf(`env variable %q could not be converted to boolean`, utils.TestWithNativeSidecarEnvVar)
	}

	type local struct {
		config             *storageframework.PerTestConfig
		volumeResource     *storageframework.VolumeResource
		volumeResourceList []*storageframework.VolumeResource
	}
	var l local
	ctx := context.Background()

	f := framework.NewFrameworkWithCustomTimeouts("node-driver-restart", storageframework.GetDriverTimeouts(driver))
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

	// CSI node driver pod restart on same node (no node reboot): create pod, verify r/w, delete node
	// driver pod so it restarts, wait for new driver ready, verify workload still has valid mount and r/w.
	ginkgo.It("should keep workload mount valid after CSI node driver pod restart on same node", func() {
		init(1)
		defer cleanup()

		ginkgo.By("Creating pod with GCS FUSE volume")
		tPod := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod.SetupVolume(l.volumeResource, volumeName, mountPath, false)
		tPod.Create(ctx)
		defer tPod.Cleanup(ctx)

		tPod.WaitForRunning(ctx)

		ginkgo.By("Verifying mount and read/write")
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("mount | grep %v | grep rw,", mountPath))
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("echo before-restart > %v/data && grep before-restart %v/data", mountPath, mountPath))

		ginkgo.By("Deleting CSI node driver pod on the node so it restarts")
		specs.RestartNodeDriverOnNode(ctx, f.ClientSet, tPod.GetNode())

		ginkgo.By("Verifying workload pod still has valid mount and can read/write")
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("mount | grep %v | grep rw,", mountPath))
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("grep before-restart %v/data", mountPath))
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("echo after-restart >> %v/data && grep after-restart %v/data", mountPath, mountPath))
	})

	// Sequential node driver restarts: restart the node driver twice and verify the workload
	// mount remains valid after each restart (catches state leaks or double-registration bugs).
	ginkgo.It("should keep workload mount valid after sequential CSI node driver restarts", func() {
		init(1)
		defer cleanup()

		ginkgo.By("Creating pod with GCS FUSE volume")
		tPod := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod.SetupVolume(l.volumeResource, volumeName, mountPath, false)
		tPod.Create(ctx)
		defer tPod.Cleanup(ctx)

		tPod.WaitForRunning(ctx)

		ginkgo.By("Verifying initial mount and read/write")
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("mount | grep %v | grep rw,", mountPath))
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("echo initial > %v/data && grep initial %v/data", mountPath, mountPath))

		ginkgo.By("First node driver restart")
		specs.RestartNodeDriverOnNode(ctx, f.ClientSet, tPod.GetNode())
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("mount | grep %v | grep rw,", mountPath))
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("grep initial %v/data", mountPath))
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("echo after-first-restart >> %v/data && grep after-first-restart %v/data", mountPath, mountPath))

		ginkgo.By("Second node driver restart")
		specs.RestartNodeDriverOnNode(ctx, f.ClientSet, tPod.GetNode())
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("mount | grep %v | grep rw,", mountPath))
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("grep initial %v/data", mountPath))
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("grep after-first-restart %v/data", mountPath))
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("echo after-second-restart >> %v/data && grep after-second-restart %v/data", mountPath, mountPath))
	})

	// Node driver restart while I/O is in progress: restart the CSI node driver on the pod's node
	// while the pod is performing I/O, then verify the mount is still valid and read/write works.
	ginkgo.It("should keep mount valid when node driver restarts while I/O is in progress", func() {
		init(1)
		defer cleanup()

		ginkgo.By("Creating pod with GCS volume")
		tPod := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod.SetupVolume(l.volumeResource, volumeName, mountPath, false)
		tPod.Create(ctx)
		defer tPod.Cleanup(ctx)

		tPod.WaitForRunning(ctx)

		ginkgo.By("Verifying initial mount and write")
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("mount | grep %v | grep rw,", mountPath))
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("echo initial > %v/initial", mountPath))

		ginkgo.By("Starting background I/O and restarting node driver during I/O")
		// Use a sentinel format "RECORD N" so partial (half-done) writes are detectable: a truncated
		// write would leave a line that doesn't match ^RECORD [0-9]+$.
		ioDone := make(chan struct{})
		go func() {
			defer close(ioDone)
			// Run I/O for ~25s; may see errors while node driver is restarting
			_, _, _ = e2epod.ExecCommandInContainerWithFullOutput(f, tPod.GetPodName(), specs.TesterContainerName, "/bin/sh", "-c",
				fmt.Sprintf("for i in $(seq 1 25); do echo \"RECORD $i\" >> %v/iofile 2>/dev/null; sleep 1; done", mountPath))
		}()

		time.Sleep(5 * time.Second)
		specs.RestartNodeDriverOnNode(ctx, f.ClientSet, tPod.GetNode())
		<-ioDone

		ginkgo.By("Verifying mount is still present and read/write works after restart")
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("mount | grep %v | grep rw,", mountPath))
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("grep initial %v/initial", mountPath))
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("echo post-restart >> %v/post && grep post-restart %v/post", mountPath, mountPath))

		// Ensure no half-done I/O: every line in iofile must be a complete record (RECORD N).
		// If the driver reverted in-flight writes we may see fewer lines but all complete; if a write
		// was left partial we get a line that doesn't match and the test fails.
		ginkgo.By("Verifying no partial (half-done) I/O in iofile: every line must be a complete RECORD N")
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName,
			fmt.Sprintf("awk '!/^RECORD [0-9]+$/{print \"INVALID:\", $0; exit 1}' %v/iofile", mountPath))
	})

	// Multiple pods on same node: restart the CSI node driver once and verify both pods still have working mounts.
	ginkgo.It("should keep multiple pods on same node working after one node driver restart", func() {
		init(2 /* volumeCount */)
		defer cleanup()

		ginkgo.By("Creating first pod with volume on node")
		tPod1 := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod1.SetupVolume(l.volumeResourceList[0], volumeName, mountPath, false)
		tPod1.Create(ctx)
		defer tPod1.Cleanup(ctx)
		tPod1.WaitForRunning(ctx)

		ginkgo.By("Creating second pod with volume on same node")
		tPod2 := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod2.SetupVolume(l.volumeResourceList[1], volumeName, mountPath, false)
		tPod2.SetNodeAffinity(tPod1.GetNode(), true /* same node */)
		tPod2.Create(ctx)
		defer tPod2.Cleanup(ctx)
		tPod2.WaitForRunning(ctx)

		ginkgo.By("Verifying both pods can read/write")
		tPod1.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("mount | grep %v | grep rw,", mountPath))
		tPod1.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("echo pod1 > %v/pod1 && grep pod1 %v/pod1", mountPath, mountPath))
		tPod2.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("mount | grep %v | grep rw,", mountPath))
		tPod2.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("echo pod2 > %v/pod2 && grep pod2 %v/pod2", mountPath, mountPath))

		ginkgo.By("Restarting CSI node driver on the node")
		specs.RestartNodeDriverOnNode(ctx, f.ClientSet, tPod1.GetNode())

		ginkgo.By("Verifying both pods still have working mounts and can read/write")
		tPod1.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("mount | grep %v | grep rw,", mountPath))
		tPod1.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("grep pod1 %v/pod1", mountPath))
		tPod1.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("echo pod1-after >> %v/pod1 && grep pod1-after %v/pod1", mountPath, mountPath))
		tPod2.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("mount | grep %v | grep rw,", mountPath))
		tPod2.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("grep pod2 %v/pod2", mountPath))
		tPod2.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("echo pod2-after >> %v/pod2 && grep pod2-after %v/pod2", mountPath, mountPath))
	})

	// Node driver restarts while sidecar is mounting: restart the node driver soon after pod create
	// so mount may be in progress; mount should either retry and succeed or fail with clear error, not hang.
	ginkgo.It("should retry or fail cleanly when node driver restarts while sidecar is mounting the bucket", func() {
		init(1)
		defer cleanup()

		ginkgo.By("Creating pod with GCS FUSE volume")
		tPod := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod.SetupVolume(l.volumeResource, volumeName, mountPath, false)
		tPod.Create(ctx)
		defer tPod.Cleanup(ctx)

		ginkgo.By("Restarting node driver once pod is scheduled (may interrupt mount)")
		restartDone := make(chan struct{})
		go func() {
			defer close(restartDone)
			var nodeName string
			for i := 0; i < 60; i++ {
				pod, err := f.ClientSet.CoreV1().Pods(f.Namespace.Name).Get(ctx, tPod.GetPodName(), metav1.GetOptions{})
				if err == nil && pod.Spec.NodeName != "" {
					nodeName = pod.Spec.NodeName
					break
				}
				time.Sleep(1 * time.Second)
			}
			gomega.Expect(nodeName).NotTo(gomega.BeEmpty(), "pod should be scheduled and have node name")
			specs.RestartNodeDriverOnNode(ctx, f.ClientSet, nodeName)
		}()

		ginkgo.By("Waiting for pod to run or fail (no hang)")
		tPod.WaitForRunning(ctx)
		<-restartDone

		ginkgo.By("Verifying mount and read/write")
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("mount | grep %v | grep rw,", mountPath))
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("echo ok > %v/data && grep ok %v/data", mountPath, mountPath))
	})

}
