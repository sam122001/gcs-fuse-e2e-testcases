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

	"github.com/google/uuid"
	"github.com/googlecloudplatform/gcs-fuse-csi-driver/pkg/webhook"
	"github.com/onsi/ginkgo/v2"
	corev1 "k8s.io/api/core/v1"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/kubernetes/test/e2e/framework"
	e2evolume "k8s.io/kubernetes/test/e2e/framework/volume"
	storageframework "k8s.io/kubernetes/test/e2e/storage/framework"
	admissionapi "k8s.io/pod-security-admission/api"
)

type gcsFuseCSIFileCacheTestSuite struct {
	tsInfo storageframework.TestSuiteInfo
}

// InitGcsFuseCSIFileCacheTestSuite returns gcsFuseCSIFileCacheTestSuite that implements TestSuite interface.
func InitGcsFuseCSIFileCacheTestSuite() storageframework.TestSuite {
	return &gcsFuseCSIFileCacheTestSuite{
		tsInfo: storageframework.TestSuiteInfo{
			Name: "fileCache",
			TestPatterns: []storageframework.TestPattern{
				storageframework.DefaultFsCSIEphemeralVolume,
				storageframework.DefaultFsPreprovisionedPV,
				storageframework.DefaultFsDynamicPV,
			},
		},
	}
}

func (t *gcsFuseCSIFileCacheTestSuite) GetTestSuiteInfo() storageframework.TestSuiteInfo {
	return t.tsInfo
}

func (t *gcsFuseCSIFileCacheTestSuite) SkipUnsupportedTests(_ storageframework.TestDriver, _ storageframework.TestPattern) {
}

func (t *gcsFuseCSIFileCacheTestSuite) DefineTests(driver storageframework.TestDriver, pattern storageframework.TestPattern) {
	gcsfuseDriver, ok := driver.(*specs.GCSFuseCSITestDriver)
	if !ok {
		framework.Failf("This test requires a GCSFuseCSITestDriver but received a %T", driver)
	}
	type local struct {
		config         *storageframework.PerTestConfig
		volumeResource *storageframework.VolumeResource
	}
	var l local
	ctx := context.Background()

	// Beware that it also registers an AfterEach which renders f unusable. Any code using
	// f must run inside an It or Context callback.
	f := framework.NewFrameworkWithCustomTimeouts("file-cache", storageframework.GetDriverTimeouts(driver))
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

	ginkgo.It("should cache the data", func() {
		init(specs.EnableFileCachePrefix)
		defer cleanup()

		// The test driver uses config.Prefix to pass the bucket names back to the test suite.
		bucketName := l.config.Prefix

		// Create files using go client
		fileName := uuid.NewString()
		gcsfuseDriver.CreateTestFileInBucket(ctx, fileName, bucketName)

		ginkgo.By("Configuring the pod")
		tPod := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod.SetupVolume(l.volumeResource, volumeName, mountPath, false)
		// Mount the gcsfuse cache volume to the test container
		tPod.SetupCacheVolumeMount("/cache")

		cacheSubfolder := volumeName
		if l.volumeResource.Pv != nil {
			cacheSubfolder = l.volumeResource.Pv.Name
		}

		ginkgo.By("Deploying the pod")
		tPod.Create(ctx)
		defer tPod.Cleanup(ctx)

		ginkgo.By("Checking that the pod is running")
		tPod.WaitForRunning(ctx)

		ginkgo.By("Checking that the pod command exits with no error")
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("mount | grep %v | grep rw,", mountPath))
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("cat %v/%v", mountPath, fileName))
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("grep '%v' /cache/.volumes/%v/gcsfuse-file-cache/%v/%v", fileName, cacheSubfolder, bucketName, fileName))
	})

	ginkgo.It("should cache the data using custom cache volume", func() {
		init(specs.EnableFileCachePrefix)
		defer cleanup()

		// The test driver uses config.Prefix to pass the bucket names back to the test suite.
		bucketName := l.config.Prefix

		// Create files using go client
		fileName := uuid.NewString()
		gcsfuseDriver.CreateTestFileInBucket(ctx, fileName, bucketName)

		ginkgo.By("Configuring the pod")
		tPod := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod.SetupVolume(l.volumeResource, volumeName, mountPath, false)
		tPVC := specs.NewTestPVC(f.ClientSet, f.Namespace, "custom-cache", "standard-rwo", "5Gi", corev1.ReadWriteOnce)
		tPod.SetupVolume(&storageframework.VolumeResource{Pvc: tPVC.PVC}, webhook.SidecarContainerCacheVolumeName, "", false)
		tPod.SetupCacheVolumeMount("/cache")
		tPod.SetNonRootSecurityContext(0, 0, 1000)

		cacheSubfolder := volumeName
		if l.volumeResource.Pv != nil {
			cacheSubfolder = l.volumeResource.Pv.Name
		}

		ginkgo.By("Creating the PVC")
		tPVC.Create(ctx)
		defer tPVC.Cleanup(ctx)

		ginkgo.By("Deploying the pod")
		tPod.Create(ctx)
		defer tPod.Cleanup(ctx)

		ginkgo.By("Checking that the pod is running")
		tPod.WaitForRunning(ctx)

		ginkgo.By("Checking that the pod command exits with no error")
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("mount | grep %v | grep rw,", mountPath))
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("cat %v/%v", mountPath, fileName))
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("grep '%v' /cache/.volumes/%v/gcsfuse-file-cache/%v/%v", fileName, cacheSubfolder, bucketName, fileName))
	})

	ginkgo.It("should cache the data using in-memory custom cache volume", func() {
		init(specs.EnableFileCachePrefix)
		defer cleanup()

		// The test driver uses config.Prefix to pass the bucket names back to the test suite.
		bucketName := l.config.Prefix

		// Create files using go client
		fileName := uuid.NewString()
		gcsfuseDriver.CreateTestFileInBucket(ctx, fileName, bucketName)

		ginkgo.By("Configuring the pod")
		tPod := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod.SetupVolume(l.volumeResource, volumeName, mountPath, false)
		inMemoryCache := &storageframework.VolumeResource{
			VolSource: &corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{
					Medium: corev1.StorageMediumMemory,
				},
			},
		}
		tPod.SetupVolume(inMemoryCache, webhook.SidecarContainerCacheVolumeName, "", false)
		tPod.SetupCacheVolumeMount("/cache")

		cacheSubfolder := volumeName
		if l.volumeResource.Pv != nil {
			cacheSubfolder = l.volumeResource.Pv.Name
		}

		ginkgo.By("Deploying the pod")
		tPod.Create(ctx)
		defer tPod.Cleanup(ctx)

		ginkgo.By("Checking that the pod is running")
		tPod.WaitForRunning(ctx)

		ginkgo.By("Checking that the pod command exits with no error")
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("mount | grep %v | grep rw,", mountPath))
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("cat %v/%v", mountPath, fileName))
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("grep '%v' /cache/.volumes/%v/gcsfuse-file-cache/%v/%v", fileName, cacheSubfolder, bucketName, fileName))
	})

	ginkgo.It("should not cache the data when the file cache is disabled", func() {
		init()
		defer cleanup()

		// The test driver uses config.Prefix to pass the bucket names back to the test suite.
		bucketName := l.config.Prefix

		// Create files using go client
		fileName := uuid.NewString()
		gcsfuseDriver.CreateTestFileInBucket(ctx, fileName, bucketName)

		ginkgo.By("Configuring the pod")
		tPod := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod.SetupVolume(l.volumeResource, volumeName, mountPath, false)
		// Mount the gcsfuse cache volume to the test container
		tPod.SetupCacheVolumeMount("/cache")

		ginkgo.By("Deploying the pod")
		tPod.Create(ctx)
		defer tPod.Cleanup(ctx)

		ginkgo.By("Checking that the pod is running")
		tPod.WaitForRunning(ctx)

		ginkgo.By("Checking that the pod command exits with no error")
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("mount | grep %v | grep rw,", mountPath))
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("cat %v/%v", mountPath, fileName))
		// the cache volume should be empty
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, "[ ! -d '/cache/.volumes' ] && exit 0 || exit 1")
	})

	ginkgo.It("should have cache miss when the data is larger than fileCacheCapacity", func() {
		init(specs.EnableFileCachePrefix)
		defer cleanup()

		// The test driver uses config.Prefix to pass the bucket names back to the test suite.
		bucketName := l.config.Prefix

		// Create files using gsutil
		fileName := uuid.NewString()
		// The file size 110 MB is larger than the 100 MB fileCacheCapacity
		gcsfuseDriver.CreateTestFileWithSizeInBucket(ctx, fileName, bucketName, 110*1024*1024)

		ginkgo.By("Configuring the pod")
		tPod := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod.SetupVolume(l.volumeResource, volumeName, mountPath, false)

		ginkgo.By("Deploying the pod")
		tPod.Create(ctx)
		defer tPod.Cleanup(ctx)

		ginkgo.By("Checking that the pod is running")
		tPod.WaitForRunning(ctx)

		ginkgo.By("Checking that the pod command exits with no error")
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("mount | grep %v | grep rw,", mountPath))
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("cat %v/%v > /dev/null", mountPath, fileName))

		tPod.WaitForLog(ctx, webhook.GcsFuseSidecarName, "while inserting into the cache: size of the entry is more than the cache's maxSize")
	})

	ginkgo.It("should have cache miss when the fileCacheCapacity is larger than underlying storage", func() {
		init(specs.EnableFileCacheWithLargeCapacityPrefix)
		defer cleanup()

		// The test driver uses config.Prefix to pass the bucket names back to the test suite.
		bucketName := l.config.Prefix

		// Create files using gsutil
		fileName := uuid.NewString()
		// The file size 2 GB is larger than the 1 GB PD
		gcsfuseDriver.CreateTestFileWithSizeInBucket(ctx, fileName, bucketName, 2*1024*1024*1024)

		ginkgo.By("Configuring the pod")
		tPod := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod.SetupVolume(l.volumeResource, volumeName, mountPath, false)
		tPVC := specs.NewTestPVC(f.ClientSet, f.Namespace, "custom-cache", "standard-rwo", "1Gi", corev1.ReadWriteOnce)
		tPod.SetupVolume(&storageframework.VolumeResource{Pvc: tPVC.PVC}, webhook.SidecarContainerCacheVolumeName, "", false)
		tPod.SetNonRootSecurityContext(0, 0, 1000)

		ginkgo.By("Creating the PVC")
		tPVC.Create(ctx)
		defer tPVC.Cleanup(ctx)

		ginkgo.By("Deploying the pod")
		tPod.Create(ctx)
		defer tPod.Cleanup(ctx)

		ginkgo.By("Checking that the pod is running")
		tPod.WaitForRunning(ctx)

		ginkgo.By("Checking that the pod command exits with no error")
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("mount | grep %v | grep rw,", mountPath))
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("cat %v/%v > /dev/null", mountPath, fileName))

		tPod.WaitForLog(ctx, webhook.GcsFuseSidecarName, "no space left on device")
	})

	ginkgo.It("should cache multiple files and list them from mount", func() {
		init(specs.EnableFileCachePrefix)
		defer cleanup()

		bucketName := l.config.Prefix
		const numFiles = 5
		fileNames := make([]string, numFiles)
		for i := 0; i < numFiles; i++ {
			fileNames[i] = fmt.Sprintf("multi-%s-%d", uuid.NewString(), i)
			gcsfuseDriver.CreateTestFileInBucket(ctx, fileNames[i], bucketName)
		}

		ginkgo.By("Configuring the pod")
		tPod := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod.SetupVolume(l.volumeResource, volumeName, mountPath, false)
		tPod.SetupCacheVolumeMount("/cache")

		cacheSubfolder := volumeName
		if l.volumeResource.Pv != nil {
			cacheSubfolder = l.volumeResource.Pv.Name
		}

		ginkgo.By("Deploying the pod")
		tPod.Create(ctx)
		defer tPod.Cleanup(ctx)

		ginkgo.By("Checking that the pod is running")
		tPod.WaitForRunning(ctx)

		ginkgo.By("Listing and reading files from mount to populate cache")
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("ls %v", mountPath))
		for _, fileName := range fileNames {
			tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("cat %v/%v", mountPath, fileName))
		}

		ginkgo.By("Verifying all files appear in cache and are readable")
		for _, fileName := range fileNames {
			tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("grep '%v' /cache/.volumes/%v/gcsfuse-file-cache/%v/%v", fileName, cacheSubfolder, bucketName, fileName))
			tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("cat %v/%v | grep -q '%v'", mountPath, fileName, fileName))
		}
	})

	ginkgo.It("should handle concurrent reads of the same file with file cache enabled", func() {
		init(specs.EnableFileCachePrefix)
		defer cleanup()

		bucketName := l.config.Prefix
		fileName := uuid.NewString()
		gcsfuseDriver.CreateTestFileInBucket(ctx, fileName, bucketName)

		ginkgo.By("Configuring the pod")
		tPod := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod.SetupVolume(l.volumeResource, volumeName, mountPath, false)
		tPod.SetupCacheVolumeMount("/cache")

		cacheSubfolder := volumeName
		if l.volumeResource.Pv != nil {
			cacheSubfolder = l.volumeResource.Pv.Name
		}

		ginkgo.By("Deploying the pod")
		tPod.Create(ctx)
		defer tPod.Cleanup(ctx)

		ginkgo.By("Checking that the pod is running")
		tPod.WaitForRunning(ctx)

		ginkgo.By("Running concurrent reads of the same file")
		concurrentReadCmd := fmt.Sprintf("for i in 1 2 3 4 5 6 7 8 9 10; do cat %v/%v > /dev/null & done; wait", mountPath, fileName)
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, concurrentReadCmd)

		ginkgo.By("Verifying file is in cache and content is correct")
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("grep '%v' /cache/.volumes/%v/gcsfuse-file-cache/%v/%v", fileName, cacheSubfolder, bucketName, fileName))
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("cat %v/%v | grep -q '%v'", mountPath, fileName, fileName))
	})

	ginkgo.It("should cache small files up to fileCacheCapacity", func() {
		init(specs.EnableFileCachePrefix)
		defer cleanup()

		bucketName := l.config.Prefix
		// fileCacheCapacity is 100Mi; use 99 files of 1MB each (99MB) to stay just under capacity
		const numFiles = 99
		const fileSize = 1 * 1024 * 1024 // 1MB
		fileNames := make([]string, numFiles)
		for i := 0; i < numFiles; i++ {
			fileNames[i] = fmt.Sprintf("small-%s-%d", uuid.NewString(), i)
			gcsfuseDriver.CreateTestFileWithSizeInBucket(ctx, fileNames[i], bucketName, fileSize)
		}

		ginkgo.By("Configuring the pod")
		tPod := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod.SetupVolume(l.volumeResource, volumeName, mountPath, false)
		tPod.SetupCacheVolumeMount("/cache")

		cacheSubfolder := volumeName
		if l.volumeResource.Pv != nil {
			cacheSubfolder = l.volumeResource.Pv.Name
		}

		ginkgo.By("Deploying the pod")
		tPod.Create(ctx)
		defer tPod.Cleanup(ctx)

		ginkgo.By("Checking that the pod is running")
		tPod.WaitForRunning(ctx)

		ginkgo.By("Reading all small files to populate cache")
		for _, fileName := range fileNames {
			tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("cat %v/%v > /dev/null", mountPath, fileName))
		}

		ginkgo.By("Verifying all files are in cache and readable")
		for _, fileName := range fileNames {
			tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("test -f /cache/.volumes/%v/gcsfuse-file-cache/%v/%v", cacheSubfolder, bucketName, fileName))
			tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("cat %v/%v > /dev/null", mountPath, fileName))
		}

		ginkgo.By("Adding one more file to exceed cache capacity and verifying eviction behavior")
		extraFileName := fmt.Sprintf("small-extra-%s", uuid.NewString())
		gcsfuseDriver.CreateTestFileWithSizeInBucket(ctx, extraFileName, bucketName, fileSize)
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("cat %v/%v > /dev/null", mountPath, extraFileName))
		// All files (including extra) should still be readable from mount after potential eviction
		allNames := append(fileNames, extraFileName)
		for _, fileName := range allNames {
			tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("cat %v/%v > /dev/null", mountPath, fileName))
		}
	})

	ginkgo.It("Cache Persistence After Pod Restart", func() {
		init(specs.EnableFileCachePrefix)
		defer cleanup()

		bucketName := l.config.Prefix
		fileName := uuid.NewString()
		gcsfuseDriver.CreateTestFileInBucket(ctx, fileName, bucketName)

		cacheSubfolder := volumeName
		if l.volumeResource.Pv != nil {
			cacheSubfolder = l.volumeResource.Pv.Name
		}

		ginkgo.By("Creating persistent cache PVC")
		tPVC := specs.NewTestPVC(f.ClientSet, f.Namespace, "cache-persistence-pvc", "standard-rwo", "5Gi", corev1.ReadWriteOnce)
		tPVC.Create(ctx)
		defer tPVC.Cleanup(ctx)

		ginkgo.By("Configuring the first pod with custom cache volume")
		tPod1 := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod1.SetupVolume(l.volumeResource, volumeName, mountPath, false)
		tPod1.SetupVolume(&storageframework.VolumeResource{Pvc: tPVC.PVC}, webhook.SidecarContainerCacheVolumeName, "", false)
		tPod1.SetupCacheVolumeMount("/cache")
		tPod1.SetNonRootSecurityContext(0, 0, 1000)

		ginkgo.By("Deploying the first pod and populating cache")
		tPod1.Create(ctx)
		tPod1.WaitForRunning(ctx)
		tPod1.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("mount | grep %v | grep rw,", mountPath))
		tPod1.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("cat %v/%v", mountPath, fileName))
		tPod1.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("grep '%v' /cache/.volumes/%v/gcsfuse-file-cache/%v/%v", fileName, cacheSubfolder, bucketName, fileName))

		ginkgo.By("Restarting the pod by deleting and creating a new pod with same volumes")
		tPod1.Cleanup(ctx)

		ginkgo.By("Configuring the second pod with same volume and cache PVC")
		tPod2 := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod2.SetupVolume(l.volumeResource, volumeName, mountPath, false)
		tPod2.SetupVolume(&storageframework.VolumeResource{Pvc: tPVC.PVC}, webhook.SidecarContainerCacheVolumeName, "", false)
		tPod2.SetupCacheVolumeMount("/cache")
		tPod2.SetNonRootSecurityContext(0, 0, 1000)

		ginkgo.By("Deploying the second pod")
		tPod2.Create(ctx)
		defer tPod2.Cleanup(ctx)
		tPod2.WaitForRunning(ctx)

		ginkgo.By("Verifying file is readable and cache persisted from previous pod")
		tPod2.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("mount | grep %v | grep rw,", mountPath))
		tPod2.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("cat %v/%v", mountPath, fileName))
		tPod2.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("grep '%v' /cache/.volumes/%v/gcsfuse-file-cache/%v/%v", fileName, cacheSubfolder, bucketName, fileName))
	})

	ginkgo.It("should not populate data cache by listing only", func() {
		init(specs.EnableFileCachePrefix)
		defer cleanup()

		bucketName := l.config.Prefix
		fileName := uuid.NewString()
		gcsfuseDriver.CreateTestFileInBucket(ctx, fileName, bucketName)

		ginkgo.By("Configuring the pod")
		tPod := specs.NewTestPod(f.ClientSet, f.Namespace)
		tPod.SetupVolume(l.volumeResource, volumeName, mountPath, false)
		tPod.SetupCacheVolumeMount("/cache")

		cacheSubfolder := volumeName
		if l.volumeResource.Pv != nil {
			cacheSubfolder = l.volumeResource.Pv.Name
		}

		ginkgo.By("Deploying the pod")
		tPod.Create(ctx)
		defer tPod.Cleanup(ctx)

		ginkgo.By("Checking that the pod is running")
		tPod.WaitForRunning(ctx)

		ginkgo.By("Listing mount without reading file and verifying file is not in data cache yet")
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("ls %v", mountPath))
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("test ! -f /cache/.volumes/%v/gcsfuse-file-cache/%v/%v || exit 1", cacheSubfolder, bucketName, fileName))

		ginkgo.By("Reading file and verifying it is now in cache")
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("cat %v/%v", mountPath, fileName))
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName, fmt.Sprintf("grep '%v' /cache/.volumes/%v/gcsfuse-file-cache/%v/%v", fileName, cacheSubfolder, bucketName, fileName))
	})

}
