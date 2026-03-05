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
	e2eskipper "k8s.io/kubernetes/test/e2e/framework/skipper"
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
		klog.Fatalf(`env variable "%s" could not be converted to boolean`, utils.TestWithNativeSidecarEnvVar)
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

	// Node driver restarts while metadata prefetch is in use. In native sidecar mode the node
	// driver restart must NOT disrupt the sidecar-mounted gcsfuse instance:
	//   - gcsfuse continues running (mount stays present and rw)
	//   - metadata cache stays untouched (no extra rebuild triggered by the restart)
	//   - directory state remains consistent and data is not corrupted.
	// This test checks "no disruption + no stale metadata + no corruption".
	ginkgo.It("[metadata prefetch] should keep metadata cache and directory state consistent across node driver restart without stale results or corruption", func() {
		if !supportsNativeSidecar {
			e2eskipper.Skipf("metadata prefetch requires native sidecar")
		}
		init(1, specs.EnableMetadataPrefetchPrefix)
		defer cleanup()

		ginkgo.By("Creating pod with metadata prefetch volume")
		tPod := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod.SetupVolume(l.volumeResource, volumeName, mountPath, false)
		tPod.Create(ctx)
		defer tPod.Cleanup(ctx)

		tPod.WaitForRunning(ctx)

		ginkgo.By("Writing file and priming metadata cache (ls, stat)")
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("echo before-restart > %v/prefetch-test", mountPath))
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("ls -la %v && stat %v/prefetch-test", mountPath, mountPath))

		ginkgo.By("Restarting CSI node driver on the node")
		specs.RestartNodeDriverOnNode(ctx, f.ClientSet, tPod.GetNode())

		ginkgo.By("Verifying mount and metadata are unchanged after restart (no disruption, no stale results, no corruption)")
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("mount | grep %v | grep rw,", mountPath))
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("grep before-restart %v/prefetch-test", mountPath))
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("ls -la %v | grep prefetch-test", mountPath))
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("echo after-restart >> %v/prefetch-test && grep after-restart %v/prefetch-test", mountPath, mountPath))
	})

	// Node driver restarts under resource pressure: run moderate CPU load on the same node,
	// restart the node driver, then verify the workload pod still has a valid mount and can do I/O.
	ginkgo.It("[Disruptive] should Mount remains stable when CSI Node restarts under high CPU load on the node", func() {
		init(1)
		defer cleanup()

		ginkgo.By("Creating pod with GCS FUSE volume")
		tPod := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod.SetupVolume(l.volumeResource, volumeName, mountPath, false)
		tPod.Create(ctx)
		defer tPod.Cleanup(ctx)

		tPod.WaitForRunning(ctx)
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("echo before-stress > %v/data", mountPath))

		ginkgo.By("Creating stress pod on same node to apply moderate CPU load")
		stressPod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "node-driver-restart-stress",
				Namespace: f.Namespace.Name,
			},
			Spec: corev1.PodSpec{
				RestartPolicy: corev1.RestartPolicyNever,
				NodeName:      tPod.GetNode(),
				Containers: []corev1.Container{
					{
						Name:    "stress",
						Image:   specs.UbuntuImage,
						Command: []string{"/bin/bash", "-c", "for i in $(seq 1 90); do dd if=/dev/zero of=/dev/null bs=1M count=50 2>/dev/null; sleep 1; done"},
					},
				},
			},
		}
		_, createErr := f.ClientSet.CoreV1().Pods(f.Namespace.Name).Create(ctx, stressPod, metav1.CreateOptions{})
		framework.ExpectNoError(createErr)
		defer func() {
			_ = f.ClientSet.CoreV1().Pods(f.Namespace.Name).Delete(ctx, stressPod.Name, metav1.DeleteOptions{})
		}()

		ginkgo.By("Waiting for stress pod to be running")
		framework.ExpectNoError(e2epod.WaitTimeoutForPodRunningInNamespace(ctx, f.ClientSet, stressPod.Name, f.Namespace.Name, 1*time.Minute))

		ginkgo.By("Restarting CSI node driver while node is under load")
		specs.RestartNodeDriverOnNode(ctx, f.ClientSet, tPod.GetNode())

		ginkgo.By("Verifying workload pod still has valid mount and can read/write")
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("mount | grep %v | grep rw,", mountPath))
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("grep before-stress %v/data", mountPath))
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("echo after-stress >> %v/data && grep after-stress %v/data", mountPath, mountPath))
	})

	// After node driver restart, unmount (delete pod) then mount a new pod on the same node.
	// Ensures clean teardown and that new pods can mount volumes on the node after a restart (critical for rescheduling).
	ginkgo.It("should allow pod to unmount and new pod to mount on same node after node driver restart", func() {
		init(2)
		defer cleanup()

		ginkgo.By("Creating first pod with GCS FUSE volume")
		tPod1 := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod1.SetupVolume(l.volumeResourceList[0], volumeName, mountPath, false)
		tPod1.Create(ctx)
		tPod1.WaitForRunning(ctx)

		ginkgo.By("Verifying first pod mount and read/write")
		tPod1.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("mount | grep %v | grep rw,", mountPath))
		tPod1.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("echo first-pod > %v/data && grep first-pod %v/data", mountPath, mountPath))

		ginkgo.By("Restarting CSI node driver on the node")
		specs.RestartNodeDriverOnNode(ctx, f.ClientSet, tPod1.GetNode())
		nodeName := tPod1.GetNode()

		ginkgo.By("Deleting first pod (unmount) so node driver performs cleanup")
		tPod1.Cleanup(ctx)

		ginkgo.By("Creating second pod with new volume on same node")
		tPod2 := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod2.SetupVolume(l.volumeResourceList[1], volumeName, mountPath, false)
		tPod2.SetNodeAffinity(nodeName, true)
		tPod2.Create(ctx)
		defer tPod2.Cleanup(ctx)
		tPod2.WaitForRunning(ctx)

		ginkgo.By("Verifying second pod has valid mount and can read/write")
		tPod2.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("mount | grep %v | grep rw,", mountPath))
		tPod2.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("echo second-pod > %v/data && grep second-pod %v/data", mountPath, mountPath))
	})
}
