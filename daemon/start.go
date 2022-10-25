package daemon // import "github.com/docker/docker/daemon"

import (
	"context"
	"fmt"
	"github.com/docker/docker/layer"
	volumeopts "github.com/docker/docker/volume/service/opts"
	"github.com/opencontainers/go-digest"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/docker/docker/api/types"
	containertypes "github.com/docker/docker/api/types/container"
	"github.com/docker/docker/container"
	"github.com/docker/docker/errdefs"
	"github.com/docker/docker/pkg/mount"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	image "github.com/docker/docker/image"
)

var supportedAlg = []digest.Algorithm{
	digest.SHA256,
	// digest.SHA384, // Currently not used
	// digest.SHA512, // Currently not used
}

// ContainerStart starts a container.
func (daemon *Daemon) ContainerStart(name string, hostConfig *containertypes.HostConfig, checkpoint string, checkpointDir string) error {
	if checkpoint != "" && !daemon.HasExperimental() {
		return errdefs.InvalidParameter(errors.New("checkpoint is only supported in experimental mode"))
	}

	container, err := daemon.GetContainer(name)
	if err != nil {
		if errdefs.GetHTTPErrorStatusCode(err) == http.StatusNotFound {
			dir, rd_err := ioutil.ReadDir(daemon.repository)
			if rd_err != nil {
				return rd_err
			}
			var full_ct_id = ""
			for _, v := range dir {
				id := v.Name()
				logrus.Debugf("container_id:%s", v.Name())
				if strings.Contains(id, name) {
					full_ct_id = id
					break
				}

			}
			if full_ct_id == "" {
				return err
			}
			logrus.Debugf("full_ct_id:%s", full_ct_id)
			//Get Container's diff-ids
			diff_ids := []string{}

			logrus.Debugf("daemon.root:%s", daemon.root)
			//logrus.Debugf("container.OS:%s", daemon.graphDrivers[container.OS])

			layerdb_root := filepath.Join(daemon.root, "image", daemon.graphDrivers[runtime.GOOS], "layerdb")
			// layerdb_root := filepath.Join(daemon.root, "image", "overlay2", "layerdb") //get the right fs name?
			logrus.Debugf("layerdb_root:%s", layerdb_root)

			for _, algorithm := range supportedAlg {
				parent_path := filepath.Join(layerdb_root, "mounts", full_ct_id, "parent")
				for err = nil; err == nil; _, err = os.Stat(parent_path) {
					f, err := os.Open(parent_path)
					defer f.Close()
					if err != nil {
						return err
					}
					parent_id, _ := ioutil.ReadAll(f)
					parent_id = parent_id[7:]
					diff_ids = append(diff_ids, string(parent_id))
					parent_path = filepath.Join(layerdb_root, string(algorithm), string(parent_id), "parent")

				}
			}
			//Load LayerStore
			for _, diff_id := range diff_ids {
				logrus.Debugf("Load LayerStore diff_id:%s", diff_id)
				var diff_chainID layer.ChainID
				for _, algorithm := range supportedAlg {
					dgst := digest.NewDigestFromHex(string(algorithm), diff_id)
					if err := dgst.Validate(); err != nil {
						logrus.Debugf("Ignoring digest %s :%s ", algorithm, diff_id)
					} else {
						diff_chainID = layer.ChainID(dgst)
					}
				}
				daemon.imageService.GetLayer(diff_chainID, runtime.GOOS)
			}
			// Load RWLayer mounts
			logrus.Debugf("Load RWLayer!")
			//daemon.layerStore.LoadMount(full_ct_id)
			daemon.imageService.LoadMount(full_ct_id, runtime.GOOS)

			//Load Container
			rst_container, err := daemon.load(full_ct_id)

			if err != nil {
				logrus.Errorf("Failed to load container %v :%v", full_ct_id, err)
			}
			logrus.Debugf("Succeed to load container %v", full_ct_id)

			//Load ImageStore
			logrus.Debugf("Load ImageStore!")
			image_digest := string(rst_container.ImageID)
			image_id := image.ID(image_digest[(strings.Index(image_digest, ":") + 1):])
			logrus.Debugf("Load ImageStore : %s", image_id)
			img_err := daemon.imageService.AddImage(image_id)
			if img_err != nil {
				logrus.Errorf("Failed to load ImageStore %v :%v", image_id, img_err)
			}
			logrus.Debugf("Succeed to load ImageStore %v", image_id)

			//Register container
			currentDriver := daemon.imageService.GraphDriverForOS(runtime.GOOS)
			if rst_container.Driver == "" && currentDriver == "aufs" || rst_container.Driver == currentDriver {
				rwlayer, err := daemon.imageService.GetLayerByID(full_ct_id, runtime.GOOS)
				if err != nil {
					logrus.Errorf("Failed to load RWLayer mounts %v:%v", full_ct_id, err)
				}
				rst_container.RWLayer = rwlayer
				logrus.Debugf("Loaded container mounts %v", rst_container.ID)
			} else {
				logrus.Debugf("Cannot load container %s because it was created with another graph driver that cannot match current graph driver", rst_container.ID)
			}

			if err := daemon.registerName(rst_container); err != nil {
				logrus.Debugf("Failed to register container %s :%s", rst_container.ID, err)
			}
			daemon.Register(rst_container)
			logrus.Debugf("Succeed to Register container %v", rst_container.ID)
			//if err := daemon.verifyVolumesInfo(rst_container); err != nil {
			//	logrus.Errorf("Failed to verify volumes for container '%s':%v", rst_container.ID, err)
			//}
			if rst_container.HostConfig.LogConfig.Type == "" {
				if err := daemon.mergeAndVerifyLogConfig(&rst_container.HostConfig.LogConfig); err != nil {
					logrus.Errorf("Failed to verify log config for container %s :%q", rst_container.ID, err)
				}
			}

			logrus.Debugf("restored container.MountPoints:%v", rst_container.MountPoints)
			//Register Volume : configure driver(local/other)
			for _, volume := range rst_container.MountPoints {
				logrus.Debugf("Start Get Volume Driver")
				//vd, err := volumedrivers.GetDriver(volume.Driver)
				vd, err := daemon.volumes.VolGetDriver(volume.Driver)
				if err != nil {
					return fmt.Errorf("can't retrieve local volume :%v", err)
				}
				logrus.Debugf("Start add Volume:%s", volume.Name)
				vd.Add(volume.Name, nil)
				daemon.volumes.Create(context.TODO(), volume.Name, volume.Driver, volumeopts.WithCreateReference(rst_container.ID))
			}

			container, err = daemon.GetContainer(name)
			if err != nil {
				return err
			}
			logrus.Debugf("Succeed to Get rst_container %v", container.ID)
			if checkpoint != "" || checkpointDir != "" {
				daemon.Unmount(container)
			}
			logrus.Debugf("Succeed to Unmount container %v", container.ID)

		} else {
			return err
		}
	}

	validateState := func() error {
		container.Lock()
		defer container.Unlock()

		if container.Paused {
			return errdefs.Conflict(errors.New("cannot start a paused container, try unpause instead"))
		}

		if container.Running {
			return containerNotModifiedError{running: true}
		}

		if container.RemovalInProgress || container.Dead {
			return errdefs.Conflict(errors.New("container is marked for removal and cannot be started"))
		}
		return nil
	}

	if err := validateState(); err != nil {
		return err
	}

	// Windows does not have the backwards compatibility issue here.
	if runtime.GOOS != "windows" {
		// This is kept for backward compatibility - hostconfig should be passed when
		// creating a container, not during start.
		if hostConfig != nil {
			logrus.Warn("DEPRECATED: Setting host configuration options when the container starts is deprecated and has been removed in Docker 1.12")
			oldNetworkMode := container.HostConfig.NetworkMode
			if err := daemon.setSecurityOptions(container, hostConfig); err != nil {
				return errdefs.InvalidParameter(err)
			}
			if err := daemon.mergeAndVerifyLogConfig(&hostConfig.LogConfig); err != nil {
				return errdefs.InvalidParameter(err)
			}
			if err := daemon.setHostConfig(container, hostConfig); err != nil {
				return errdefs.InvalidParameter(err)
			}
			newNetworkMode := container.HostConfig.NetworkMode
			if string(oldNetworkMode) != string(newNetworkMode) {
				// if user has change the network mode on starting, clean up the
				// old networks. It is a deprecated feature and has been removed in Docker 1.12
				container.NetworkSettings.Networks = nil
				if err := container.CheckpointTo(daemon.containersReplica); err != nil {
					return errdefs.System(err)
				}
			}
			container.InitDNSHostConfig()
		}
	} else {
		if hostConfig != nil {
			return errdefs.InvalidParameter(errors.New("Supplying a hostconfig on start is not supported. It should be supplied on create"))
		}
	}

	// check if hostConfig is in line with the current system settings.
	// It may happen cgroups are umounted or the like.
	if _, err = daemon.verifyContainerSettings(runtime.GOOS, container.HostConfig, nil, false); err != nil {
		return errdefs.InvalidParameter(err)
	}
	// Adapt for old containers in case we have updates in this function and
	// old containers never have chance to call the new function in create stage.
	if hostConfig != nil {
		if err := daemon.adaptContainerSettings(container.HostConfig, false); err != nil {
			return errdefs.InvalidParameter(err)
		}
	}
	return daemon.containerStart(container, checkpoint, checkpointDir, true)
}

// containerStart prepares the container to run by setting up everything the
// container needs, such as storage and networking, as well as links
// between containers. The container is left waiting for a signal to
// begin running.
func (daemon *Daemon) containerStart(container *container.Container, checkpoint string, checkpointDir string, resetRestartManager bool) (err error) {
	start := time.Now()
	container.Lock()
	defer container.Unlock()

	if resetRestartManager && container.Running { // skip this check if already in restarting step and resetRestartManager==false
		return nil
	}

	if container.RemovalInProgress || container.Dead {
		return errdefs.Conflict(errors.New("container is marked for removal and cannot be started"))
	}

	if checkpointDir != "" {
		// TODO(mlaventure): how would we support that?
		return errdefs.Forbidden(errors.New("custom checkpointdir is not supported"))
	}

	// if we encounter an error during start we need to ensure that any other
	// setup has been cleaned up properly
	defer func() {
		if err != nil {
			container.SetError(err)
			// if no one else has set it, make sure we don't leave it at zero
			if container.ExitCode() == 0 {
				container.SetExitCode(128)
			}
			if err := container.CheckpointTo(daemon.containersReplica); err != nil {
				logrus.Errorf("%s: failed saving state on start failure: %v", container.ID, err)
			}
			container.Reset(false)

			daemon.Cleanup(container)
			// if containers AutoRemove flag is set, remove it after clean up
			if container.HostConfig.AutoRemove {
				container.Unlock()
				if err := daemon.ContainerRm(container.ID, &types.ContainerRmConfig{ForceRemove: true, RemoveVolume: true}); err != nil {
					logrus.Errorf("can't remove container %s: %v", container.ID, err)
				}
				container.Lock()
			}
		}
	}()

	if err := daemon.conditionalMountOnStart(container); err != nil {
		return err
	}

	if err := daemon.initializeNetworking(container); err != nil {
		return err
	}

	spec, err := daemon.createSpec(container)
	if err != nil {
		return errdefs.System(err)
	}

	if resetRestartManager {
		container.ResetRestartManager(true)
		container.HasBeenManuallyStopped = false
	}

	if err := daemon.saveApparmorConfig(container); err != nil {
		return err
	}

	if checkpoint != "" {
		checkpointDir, err = getCheckpointDir(checkpointDir, checkpoint, container.Name, container.ID, container.CheckpointDir(), false)
		if err != nil {
			return err
		}
	}

	createOptions, err := daemon.getLibcontainerdCreateOptions(container)
	if err != nil {
		return err
	}

	ctx := context.TODO()

	err = daemon.containerd.Create(ctx, container.ID, spec, createOptions)
	if err != nil {
		if errdefs.IsConflict(err) {
			logrus.WithError(err).WithField("container", container.ID).Error("Container not cleaned up from containerd from previous run")
			// best effort to clean up old container object
			daemon.containerd.DeleteTask(ctx, container.ID)
			if err := daemon.containerd.Delete(ctx, container.ID); err != nil && !errdefs.IsNotFound(err) {
				logrus.WithError(err).WithField("container", container.ID).Error("Error cleaning up stale containerd container object")
			}
			err = daemon.containerd.Create(ctx, container.ID, spec, createOptions)
		}
		if err != nil {
			return translateContainerdStartErr(container.Path, container.SetExitCode, err)
		}
	}

	// TODO(mlaventure): we need to specify checkpoint options here
	pid, err := daemon.containerd.Start(context.Background(), container.ID, checkpointDir,
		container.StreamConfig.Stdin() != nil || container.Config.Tty,
		container.InitializeStdio)
	if err != nil {
		if err := daemon.containerd.Delete(context.Background(), container.ID); err != nil {
			logrus.WithError(err).WithField("container", container.ID).
				Error("failed to delete failed start container")
		}
		return translateContainerdStartErr(container.Path, container.SetExitCode, err)
	}

	container.SetRunning(pid, true)
	container.HasBeenStartedBefore = true
	daemon.setStateCounter(container)

	daemon.initHealthMonitor(container)

	if err := container.CheckpointTo(daemon.containersReplica); err != nil {
		logrus.WithError(err).WithField("container", container.ID).
			Errorf("failed to store container")
	}

	daemon.LogContainerEvent(container, "start")
	containerActions.WithValues("start").UpdateSince(start)

	return nil
}

// Cleanup releases any network resources allocated to the container along with any rules
// around how containers are linked together.  It also unmounts the container's root filesystem.
func (daemon *Daemon) Cleanup(container *container.Container) {
	daemon.releaseNetwork(container)

	if err := container.UnmountIpcMount(); err != nil {
		logrus.Warnf("%s cleanup: failed to unmount IPC: %s", container.ID, err)
	}

	if err := daemon.conditionalUnmountOnCleanup(container); err != nil {
		// FIXME: remove once reference counting for graphdrivers has been refactored
		// Ensure that all the mounts are gone
		if mountid, err := daemon.imageService.GetLayerMountID(container.ID, runtime.GOOS); err == nil {
			daemon.cleanupMountsByID(mountid)
		}
	}

	if err := container.UnmountSecrets(); err != nil {
		logrus.Warnf("%s cleanup: failed to unmount secrets: %s", container.ID, err)
	}

	if err := mount.RecursiveUnmount(container.Root); err != nil {
		logrus.WithError(err).WithField("container", container.ID).Warn("Error while cleaning up container resource mounts.")
	}

	for _, eConfig := range container.ExecCommands.Commands() {
		daemon.unregisterExecCommand(container, eConfig)
	}

	if container.BaseFS != nil && container.BaseFS.Path() != "" {
		if err := container.UnmountVolumes(daemon.LogVolumeEvent); err != nil {
			logrus.Warnf("%s cleanup: Failed to umount volumes: %v", container.ID, err)
		}
	}

	container.CancelAttachContext()

	if err := daemon.containerd.Delete(context.Background(), container.ID); err != nil {
		logrus.Errorf("%s cleanup: failed to delete container from containerd: %v", container.ID, err)
	}
}
