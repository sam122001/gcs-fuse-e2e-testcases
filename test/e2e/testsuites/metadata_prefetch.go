/*
Copyright 2018 The Kubernetes Authors.
Copyright 2024 Google LLC

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

	"local/test/e2e/specs"
	"local/test/e2e/utils"

	"github.com/googlecloudplatform/gcs-fuse-csi-driver/pkg/webhook"
	"github.com/onsi/ginkgo/v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/klog/v2"
	"k8s.io/kubernetes/test/e2e/framework"
	e2eskipper "k8s.io/kubernetes/test/e2e/framework/skipper"
	e2evolume "k8s.io/kubernetes/test/e2e/framework/volume"
	storageframework "k8s.io/kubernetes/test/e2e/storage/framework"
	admissionapi "k8s.io/pod-security-admission/api"
)

type gcsFuseCSIMetadataPrefetchTestSuite struct {
	tsInfo storageframework.TestSuiteInfo
}

// InitGcsFuseCSIMetadataPrefetchTestSuite returns gcsFuseCSIMetadataPrefetchTestSuite that implements TestSuite interface.
func InitGcsFuseCSIMetadataPrefetchTestSuite() storageframework.TestSuite {
	return &gcsFuseCSIMetadataPrefetchTestSuite{
		tsInfo: storageframework.TestSuiteInfo{
			Name: "metadataPrefetch",
			TestPatterns: []storageframework.TestPattern{
				storageframework.DefaultFsCSIEphemeralVolume,
				storageframework.DefaultFsPreprovisionedPV,
			},
		},
	}
}

func (t *gcsFuseCSIMetadataPrefetchTestSuite) GetTestSuiteInfo() storageframework.TestSuiteInfo {
	return t.tsInfo
}

func (t *gcsFuseCSIMetadataPrefetchTestSuite) SkipUnsupportedTests(_ storageframework.TestDriver, _ storageframework.TestPattern) {
}

func (t *gcsFuseCSIMetadataPrefetchTestSuite) DefineTests(driver storageframework.TestDriver, pattern storageframework.TestPattern) {
	envVar := os.Getenv(utils.TestWithNativeSidecarEnvVar)
	supportsNativeSidecar, err := strconv.ParseBool(envVar)
	if err != nil {
		klog.Fatalf(`env variable "%s" could not be converted to boolean`, envVar)
	}

	type local struct {
		config         *storageframework.PerTestConfig
		volumeResource *storageframework.VolumeResource
	}
	var l local
	ctx := context.Background()

	// Beware that it also registers an AfterEach which renders f unusable. Any code using
	// f must run inside an It or Context callback.
	f := framework.NewFrameworkWithCustomTimeouts("volumes", storageframework.GetDriverTimeouts(driver))
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

	testCaseStoreAndRetainData := func(configPrefix string) {
		init(configPrefix)
		defer cleanup()

		ginkgo.By("Configuring the first pod")
		tPod1 := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod1.SetupVolume(l.volumeResource, volumeName, mountPath, false)

		ginkgo.By("Deploying the first pod")
		tPod1.Create(ctx)

		ginkgo.By("Checking that the first pod is running")
		tPod1.WaitForRunning(ctx)

		ginkgo.By("Checking that the first pod command exits with no error")
		tPod1.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("mount | grep %v | grep rw,", mountPath))
		tPod1.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("echo 'hello world' > %v/data && grep 'hello world' %v/data", mountPath, mountPath))

		ginkgo.By("Deleting the first pod")
		tPod1.Cleanup(ctx)

		ginkgo.By("Configuring the second pod")
		tPod2 := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod2.SetupVolume(l.volumeResource, volumeName, mountPath, false)

		ginkgo.By("Deploying the second pod")
		tPod2.Create(ctx)
		defer tPod2.Cleanup(ctx)

		ginkgo.By("Checking that the second pod is running")
		tPod2.WaitForRunning(ctx)

		ginkgo.By("Checking that the second pod command exits with no error")
		tPod2.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("mount | grep %v | grep rw,", mountPath))
		tPod2.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("grep 'hello world' %v/data", mountPath))

		if supportsNativeSidecar {
			ginkgo.By("Checking metadata prefetch sidecar present on the second pod")
			tPod2.VerifyMetadataPrefetchPresence()
		} else {
			ginkgo.By("Checking metadata prefetch sidecar not present on the second pod")
			tPod2.VerifyMetadataPrefetchNotPresent()
		}

		tPod2.Cleanup(ctx)
	}

	ginkgo.It("[metadata prefetch] should store data and retain the data", func() {
		if pattern.VolType == storageframework.DynamicPV {
			e2eskipper.Skipf("skip for volume type %v", storageframework.DynamicPV)
		}
		testCaseStoreAndRetainData(specs.EnableMetadataPrefetchPrefix)
	})

	testCaseListDirectoryAfterPrefetch := func(configPrefix string) {
		init(configPrefix)
		defer cleanup()

		ginkgo.By("Configuring the first pod")
		tPod1 := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod1.SetupVolume(l.volumeResource, volumeName, mountPath, false)

		ginkgo.By("Deploying the first pod")
		tPod1.Create(ctx)

		ginkgo.By("Checking that the first pod is running")
		tPod1.WaitForRunning(ctx)

		ginkgo.By("Creating multiple files and a subdirectory with a file")
		tPod1.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("mkdir -p %v/subdir && echo f1 > %v/file1 && echo f2 > %v/file2 && echo sub > %v/subdir/subfile", mountPath, mountPath, mountPath, mountPath))
		tPod1.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("ls %v | grep -E 'file1|file2|subdir'", mountPath))

		ginkgo.By("Deleting the first pod")
		tPod1.Cleanup(ctx)

		ginkgo.By("Configuring the second pod")
		tPod2 := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod2.SetupVolume(l.volumeResource, volumeName, mountPath, false)

		ginkgo.By("Deploying the second pod")
		tPod2.Create(ctx)
		defer tPod2.Cleanup(ctx)

		ginkgo.By("Checking that the second pod is running")
		tPod2.WaitForRunning(ctx)

		ginkgo.By("Listing root directory and verifying prefetched metadata shows all entries")
		tPod2.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("ls %v | grep file1 && ls %v | grep file2 && ls %v | grep subdir", mountPath, mountPath, mountPath))
		tPod2.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("ls %v/subdir | grep subfile", mountPath))
		tPod2.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("grep sub %v/subdir/subfile", mountPath))

		if supportsNativeSidecar {
			ginkgo.By("Checking metadata prefetch sidecar present on the second pod")
			tPod2.VerifyMetadataPrefetchPresence()
		} else {
			ginkgo.By("Checking metadata prefetch sidecar not present on the second pod")
			tPod2.VerifyMetadataPrefetchNotPresent()
		}
	}

	ginkgo.It("[metadata prefetch] should list directory contents correctly after metadata prefetch", func() {
		if pattern.VolType == storageframework.DynamicPV {
			e2eskipper.Skipf("skip for volume type %v", storageframework.DynamicPV)
		}
		testCaseListDirectoryAfterPrefetch(specs.EnableMetadataPrefetchPrefix)
	})

	testCaseFileMetadataAfterPrefetch := func(configPrefix string) {
		init(configPrefix)
		defer cleanup()

		ginkgo.By("Configuring the first pod")
		tPod1 := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod1.SetupVolume(l.volumeResource, volumeName, mountPath, false)

		ginkgo.By("Deploying the first pod")
		tPod1.Create(ctx)

		ginkgo.By("Checking that the first pod is running")
		tPod1.WaitForRunning(ctx)

		ginkgo.By("Creating a file with known content for metadata verification")
		content := "metadata-prefetch-test-content"
		tPod1.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("echo -n '%s' > %v/metadata-test && wc -c < %v/metadata-test", content, mountPath, mountPath))

		ginkgo.By("Deleting the first pod")
		tPod1.Cleanup(ctx)

		ginkgo.By("Configuring the second pod")
		tPod2 := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod2.SetupVolume(l.volumeResource, volumeName, mountPath, false)

		ginkgo.By("Deploying the second pod")
		tPod2.Create(ctx)
		defer tPod2.Cleanup(ctx)

		ginkgo.By("Checking that the second pod is running")
		tPod2.WaitForRunning(ctx)

		ginkgo.By("Verifying file metadata (stat) and content after prefetch")
		tPod2.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("test -f %v/metadata-test && stat %v/metadata-test", mountPath, mountPath))
		tPod2.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("grep '%s' %v/metadata-test", content, mountPath))

		if supportsNativeSidecar {
			tPod2.VerifyMetadataPrefetchPresence()
		} else {
			tPod2.VerifyMetadataPrefetchNotPresent()
		}
	}
	ginkgo.It("[metadata prefetch] should expose correct file metadata (stat) after metadata prefetch", func() {
		if pattern.VolType == storageframework.DynamicPV {
			e2eskipper.Skipf("skip for volume type %v", storageframework.DynamicPV)
		}
		testCaseFileMetadataAfterPrefetch(specs.EnableMetadataPrefetchPrefix)
	})

	testCaseNestedDirectoryAfterPrefetch := func(configPrefix string) {
		init(configPrefix)
		defer cleanup()

		ginkgo.By("Configuring the first pod")
		tPod1 := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod1.SetupVolume(l.volumeResource, volumeName, mountPath, false)

		ginkgo.By("Deploying the first pod")
		tPod1.Create(ctx)

		ginkgo.By("Checking that the first pod is running")
		tPod1.WaitForRunning(ctx)

		ginkgo.By("Creating nested directory structure and file")
		nestedPath := "level1/level2/level3"
		tPod1.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("mkdir -p %v/%s && echo nested-data > %v/%s/nested.txt", mountPath, nestedPath, mountPath, nestedPath))
		tPod1.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("grep nested-data %v/%s/nested.txt", mountPath, nestedPath))

		ginkgo.By("Deleting the first pod")
		tPod1.Cleanup(ctx)

		ginkgo.By("Configuring the second pod")
		tPod2 := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod2.SetupVolume(l.volumeResource, volumeName, mountPath, false)

		ginkgo.By("Deploying the second pod")
		tPod2.Create(ctx)
		defer tPod2.Cleanup(ctx)

		ginkgo.By("Checking that the second pod is running")
		tPod2.WaitForRunning(ctx)

		ginkgo.By("Verifying nested structure and file are visible after metadata prefetch")
		tPod2.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("find %v -name nested.txt -type f", mountPath))
		tPod2.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("grep nested-data %v/%s/nested.txt", mountPath, nestedPath))

		if supportsNativeSidecar {
			tPod2.VerifyMetadataPrefetchPresence()
		} else {
			tPod2.VerifyMetadataPrefetchNotPresent()
		}
	}

	ginkgo.It("[metadata prefetch] should retain nested directory structure after pod restart", func() {
		if pattern.VolType == storageframework.DynamicPV {
			e2eskipper.Skipf("skip for volume type %v", storageframework.DynamicPV)
		}
		testCaseNestedDirectoryAfterPrefetch(specs.EnableMetadataPrefetchPrefix)
	})

	testCaseManyFilesAfterPrefetch := func(configPrefix string) {
		init(configPrefix)
		defer cleanup()

		ginkgo.By("Configuring the first pod with many files")
		tPod1 := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod1.SetupVolume(l.volumeResource, volumeName, mountPath, false)

		ginkgo.By("Deploying the first pod")
		tPod1.Create(ctx)

		ginkgo.By("Checking that the first pod is running")
		tPod1.WaitForRunning(ctx)

		ginkgo.By("Creating many files in a single directory")
		tPod1.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("for i in $(seq 1 50); do echo file-$i > %v/file-$i; done", mountPath))

		ginkgo.By("Verifying exact files exist before prefetch")
		tPod1.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("test $(ls %v/file-* | wc -l) -eq 50", mountPath))
		tPod1.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("for i in $(seq 1 50); do test -f %v/file-$i || exit 1; done", mountPath))

		ginkgo.By("Deleting the first pod")
		tPod1.Cleanup(ctx)

		ginkgo.By("Configuring the second pod")
		tPod2 := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod2.SetupVolume(l.volumeResource, volumeName, mountPath, false)

		ginkgo.By("Deploying the second pod")
		tPod2.Create(ctx)
		defer tPod2.Cleanup(ctx)

		ginkgo.By("Checking that the second pod is running")
		tPod2.WaitForRunning(ctx)

		ginkgo.By("Verifying exact file count and that all expected files are present after prefetch")
		tPod2.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("test $(ls %v/file-* | wc -l) -eq 50", mountPath))
		tPod2.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("for i in $(seq 1 50); do test -f %v/file-$i || exit 1; done", mountPath))

		ginkgo.By("Verifying we can stat all 50 files after prefetch")
		tPod2.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("for i in $(seq 1 50); do stat %v/file-$i >/dev/null || exit 1; done", mountPath))

		if supportsNativeSidecar {
			ginkgo.By("Checking metadata prefetch sidecar present on the second pod")
			tPod2.VerifyMetadataPrefetchPresence()
		} else {
			ginkgo.By("Checking metadata prefetch sidecar not present on the second pod")
			tPod2.VerifyMetadataPrefetchNotPresent()
		}
	}

	ginkgo.It("[metadata prefetch] should handle many files in a single directory after metadata prefetch", func() {
		if pattern.VolType == storageframework.DynamicPV {
			e2eskipper.Skipf("skip for volume type %v", storageframework.DynamicPV)
		}
		testCaseManyFilesAfterPrefetch(specs.EnableMetadataPrefetchPrefix)
	})

	ginkgo.It("[metadata prefetch] should not inject metadata prefetch sidecar when feature is disabled", func() {
		if pattern.VolType == storageframework.DynamicPV {
			e2eskipper.Skipf("skip for volume type %v", storageframework.DynamicPV)
		}

		init()
		defer cleanup()

		ginkgo.By("Configuring a pod without metadata prefetch enabled")
		tPod := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod.SetupVolume(l.volumeResource, volumeName, mountPath, false)

		ginkgo.By("Deploying the pod")
		tPod.Create(ctx)
		defer tPod.Cleanup(ctx)

		ginkgo.By("Checking that the pod is running")
		tPod.WaitForRunning(ctx)

		ginkgo.By("Verifying metadata prefetch sidecar is not present when feature is disabled")
		tPod.VerifyMetadataPrefetchNotPresent()
	})

	ginkgo.It("[metadata prefetch] metadata prefetch init container should complete before heavy list/stat workload", func() {
		if pattern.VolType == storageframework.DynamicPV {
			e2eskipper.Skipf("skip for volume type %v", storageframework.DynamicPV)
		}

		if !supportsNativeSidecar {
			e2eskipper.Skipf("metadata prefetch init container is only used with native sidecar")
		}

		init(specs.EnableMetadataPrefetchPrefix)
		defer cleanup()

		ginkgo.By("Configuring the first pod to create many files")
		tPod1 := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod1.SetupVolume(l.volumeResource, volumeName, mountPath, false)

		ginkgo.By("Deploying the first pod")
		tPod1.Create(ctx)

		ginkgo.By("Checking that the first pod is running")
		tPod1.WaitForRunning(ctx)

		ginkgo.By("Creating many files to exercise metadata prefetch")
		tPod1.VerifyExecInPodSucceed(f, specs.TesterContainerName,
			fmt.Sprintf("for i in $(seq 1 100); do echo file-$i > %v/file-$i; done", mountPath))

		ginkgo.By("Deleting the first pod")
		tPod1.Cleanup(ctx)

		ginkgo.By("Configuring the second pod")
		tPod2 := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod2.SetupVolume(l.volumeResource, volumeName, mountPath, false)

		ginkgo.By("Deploying the second pod")
		tPod2.Create(ctx)
		defer tPod2.Cleanup(ctx)

		ginkgo.By("Checking that the second pod is running")
		tPod2.WaitForRunning(ctx)

		// -----------------------------
		// Init container readiness check
		// -----------------------------
		ginkgo.By("Checking metadata prefetch init container readiness status")

		pod, err := f.ClientSet.CoreV1().Pods(f.Namespace.Name).
			Get(ctx, tPod2.GetPodName(), metav1.GetOptions{})
		framework.ExpectNoError(err)

		var prefetchFound bool

		for _, cs := range pod.Status.InitContainerStatuses {
			if cs.Name == webhook.MetadataPrefetchSidecarName {
				prefetchFound = true

				ginkgo.By(fmt.Sprintf("Found metadata prefetch init container: %s", cs.Name))

				if cs.State.Terminated != nil {
					if cs.State.Terminated.ExitCode != 0 {
						ginkgo.By(fmt.Sprintf("Init container terminated with non-zero exit code: %d",
							cs.State.Terminated.ExitCode))
						framework.Failf("metadata prefetch init container exited with code %d, state: %+v",
							cs.State.Terminated.ExitCode, cs.State)
					} else {
						ginkgo.By("Init container terminated successfully with exit code 0")
					}
				} else if cs.State.Running != nil {
					ginkgo.By("Init container is currently running → considered ready for workload")
				} else {
					ginkgo.By(fmt.Sprintf("Init container is NOT ready, state: %+v", cs.State))
					framework.Failf("metadata prefetch init container not ready (expected Running or Terminated)")
				}
				break
			}
		}

		if !prefetchFound {
			ginkgo.By("Metadata prefetch init container NOT found in pod status")
			framework.Failf("metadata prefetch init container status not found in pod %s", pod.Name)
		}

		// -----------------------------
		// Run heavy stat/list workload
		// -----------------------------
		ginkgo.By("Running a heavy list/stat workload after metadata prefetch")

		tPod2.VerifyExecInPodSucceed(f, specs.TesterContainerName,
			fmt.Sprintf("test $(ls %v/file-* | wc -l) -ge 100", mountPath))

		tPod2.VerifyExecInPodSucceed(f, specs.TesterContainerName,
			fmt.Sprintf("for i in 1 20 40 60 80 100; do stat %v/file-$i >/dev/null; done", mountPath))
	})

	ginkgo.It("[metadata prefetch] should list exact file count after metadata prefetch", func() {
		if pattern.VolType == storageframework.DynamicPV {
			e2eskipper.Skipf("skip for volume type %v", storageframework.DynamicPV)
		}

		init(specs.EnableMetadataPrefetchPrefix)
		defer cleanup()

		const fileCount = 25

		ginkgo.By("Configuring the first pod")
		tPod1 := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod1.SetupVolume(l.volumeResource, volumeName, mountPath, false)

		ginkgo.By("Deploying the first pod")
		tPod1.Create(ctx)

		ginkgo.By("Checking that the first pod is running")
		tPod1.WaitForRunning(ctx)

		ginkgo.By("Creating exactly N files in a dedicated directory")
		tPod1.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("mkdir -p %v/count-test", mountPath))
		tPod1.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("for i in $(seq 1 %d); do echo $i > %v/count-test/f-$i; done", fileCount, mountPath))
		tPod1.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("test $(ls %v/count-test/ | wc -l) -eq %d", mountPath, fileCount))

		ginkgo.By("Deleting the first pod")
		tPod1.Cleanup(ctx)

		ginkgo.By("Configuring the second pod with metadata prefetch")
		tPod2 := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod2.SetupVolume(l.volumeResource, volumeName, mountPath, false)

		ginkgo.By("Deploying the second pod")
		tPod2.Create(ctx)
		defer tPod2.Cleanup(ctx)

		ginkgo.By("Checking that the second pod is running")
		tPod2.WaitForRunning(ctx)

		ginkgo.By("Verifying list after prefetch returns exact file count")
		tPod2.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("test $(ls %v/count-test/ | wc -l) -eq %d", mountPath, fileCount))

		if supportsNativeSidecar {
			tPod2.VerifyMetadataPrefetchPresence()
		} else {
			tPod2.VerifyMetadataPrefetchNotPresent()
		}
	})

	testCaseThirdPodSeesDataFromTwoPods := func(configPrefix string) {
		init(configPrefix)
		defer cleanup()

		ginkgo.By("Configuring the first pod")
		tPod1 := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod1.SetupVolume(l.volumeResource, volumeName, mountPath, false)

		ginkgo.By("Deploying the first pod")
		tPod1.Create(ctx)

		ginkgo.By("Checking that the first pod is running")
		tPod1.WaitForRunning(ctx)

		ginkgo.By("First pod writes file1")
		tPod1.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("echo from-pod1 > %v/file1", mountPath))

		ginkgo.By("Deleting the first pod")
		tPod1.Cleanup(ctx)

		ginkgo.By("Configuring the second pod")
		tPod2 := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod2.SetupVolume(l.volumeResource, volumeName, mountPath, false)

		ginkgo.By("Deploying the second pod")
		tPod2.Create(ctx)

		ginkgo.By("Checking that the second pod is running")
		tPod2.WaitForRunning(ctx)

		ginkgo.By("Second pod reads file1 and writes file2")
		tPod2.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("grep from-pod1 %v/file1", mountPath))
		tPod2.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("echo from-pod2 > %v/file2", mountPath))

		ginkgo.By("Deleting the second pod")
		tPod2.Cleanup(ctx)

		ginkgo.By("Configuring the third pod")
		tPod3 := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod3.SetupVolume(l.volumeResource, volumeName, mountPath, false)

		ginkgo.By("Deploying the third pod")
		tPod3.Create(ctx)
		defer tPod3.Cleanup(ctx)

		ginkgo.By("Checking that the third pod is running")
		tPod3.WaitForRunning(ctx)

		ginkgo.By("Third pod sees data from both first and second pod after prefetch")
		tPod3.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("ls %v | grep file1 && ls %v | grep file2", mountPath, mountPath))
		tPod3.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("grep from-pod1 %v/file1 && grep from-pod2 %v/file2", mountPath, mountPath))

		if supportsNativeSidecar {
			tPod3.VerifyMetadataPrefetchPresence()
		} else {
			tPod3.VerifyMetadataPrefetchNotPresent()
		}
	}

	ginkgo.It("[metadata prefetch] third pod should see data from both first and second pod", func() {
		if pattern.VolType == storageframework.DynamicPV {
			e2eskipper.Skipf("skip for volume type %v", storageframework.DynamicPV)
		}
		testCaseThirdPodSeesDataFromTwoPods(specs.EnableMetadataPrefetchPrefix)
	})
}
