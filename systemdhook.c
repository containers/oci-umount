#define _GNU_SOURCE
#include <stdio.h>
#include <libgen.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/mount.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sched.h>
#include <unistd.h>
#include <errno.h>
#include <linux/limits.h>
#include <selinux/selinux.h>
#include <yajl/yajl_tree.h>

#define _cleanup_(x) __attribute__((cleanup(x)))

static inline void freep(void *p) {
        free(*(void**) p);
}

static inline void closep(int *fd) {
	if (*fd > 0)
		close(*fd);
	*fd = -1;
}

static inline void fclosep(FILE **fp) {
	if (*fp)
		fclose(*fp);
	*fp = NULL;
}

#define _cleanup_free_ _cleanup_(freep)
#define _cleanup_close_ _cleanup_(closep)
#define _cleanup_fclose_ _cleanup_(fclosep)

#define DEFINE_CLEANUP_FUNC(type, func)                         \
        static inline void func##p(type *p) {                   \
                if (*p)                                         \
                        func(*p);                               \
        }                                                       \

#define pr_perror(fmt, ...) syslog(LOG_ERR, "systemdhook: " fmt ": %m\n", ##__VA_ARGS__)

#define BUFLEN 1024
#define CONFIGSZ 65536

static int makepath(char *dir, mode_t mode)
{
    if (!dir) {
	errno = EINVAL;
	return 1;
    }

    if (strlen(dir) == 1 && dir[0] == '/')
	return 0;

    makepath(dirname(strdupa(dir)), mode);

    return mkdir(dir, mode);
}

bool contains_mount(char **config_mounts, unsigned len, const char *mount) {
	for (unsigned i = 0; i < len; i++) {
		if (!strcmp(mount, config_mounts[i])) {
			fprintf(stdout, "%s already present as a mount point in container configuration, skipping\n", mount);
			return true;
		}
	}
	return false;
}

int prestart(const char *rootfs,
		const char *id,
		int pid,
		const char *mount_label,
		char **config_mounts,
		unsigned config_mounts_len)
{
	int ret = 1;
	int mfd = -1;
	int fd = -1;
	int rc = -1;
	FILE *fp = NULL;
	char *options = NULL;

	char process_mnt_ns_fd[PATH_MAX];
	snprintf(process_mnt_ns_fd, PATH_MAX, "/proc/%d/ns/mnt", pid);

	fd = open(process_mnt_ns_fd, O_RDONLY);
	if (fd < 0) {
		pr_perror("Failed to open mnt namespace fd %s", process_mnt_ns_fd);
		goto out;
	}

	/* Join the mount namespace of the target process */
	if (setns(fd, 0) == -1) {
		pr_perror("Failed to setns to %s", process_mnt_ns_fd);
		goto out;
	}
	close(fd); fd = -1;
	/* Switch to the root directory */
	if (chdir("/") == -1) {
		pr_perror("Failed to chdir");
		goto out;
	}

	char run_dir[PATH_MAX];
	snprintf(run_dir, PATH_MAX, "%s/run", rootfs);

	/* Create the /run directory */
	if (!contains_mount(config_mounts, config_mounts_len, "/run")) {
		if (mkdir(run_dir, 0755) == -1) {
			if (errno != EEXIST) {
				pr_perror("Failed to mkdir");
				goto out;
			}
		}

		if (!strcmp("", mount_label)) {
			rc = asprintf(&options, "mode=755,size=65536k");
		} else {
			rc = asprintf(&options, "mode=755,size=65536k,context=\"%s\"", mount_label);
		}
		if (rc < 0) {
			pr_perror("Failed to allocate memory for context");
			goto out;
		}

		/* Mount tmpfs at /run for systemd */
		if (mount("tmpfs", run_dir, "tmpfs", MS_NODEV|MS_NOSUID|MS_NOEXEC, options) == -1) {
			pr_perror("Failed to mount tmpfs at /run");
			goto out;
		}
	}


	char tmp_dir[PATH_MAX];
	snprintf(tmp_dir, PATH_MAX, "%s/tmp", rootfs);

	/* Create the /tmp directory */
	if (!contains_mount(config_mounts, config_mounts_len, "/tmp")) {
		if (mkdir(tmp_dir, 0755) == -1) {
			if (errno != EEXIST) {
				pr_perror("Failed to mkdir");
				goto out;
			}
		}

		if (!strcmp("", mount_label)) {
			rc = asprintf(&options, "mode=1777,size=65536k");
		} else {
			rc = asprintf(&options, "mode=1777,size=65536k,context=\"%s\"", mount_label);
		}
		if (rc < 0) {
			pr_perror("Failed to allocate memory for context");
			goto out;
		}

		/* Mount tmpfs at /tmp for systemd */
		if (mount("tmpfs", tmp_dir, "tmpfs", MS_NODEV|MS_NOSUID, options) == -1) {
			pr_perror("Failed to mount tmpfs at /tmp");
			goto out;
		}
	}

	if (!contains_mount(config_mounts, config_mounts_len, "/var/log/journal")) {
		char journal_dir[PATH_MAX];
		snprintf(journal_dir, PATH_MAX, "/var/log/journal/%.32s", id);
		char cont_journal_dir[PATH_MAX];
		snprintf(cont_journal_dir, PATH_MAX, "%s%s", rootfs, journal_dir);
		if (makepath(journal_dir, 0755) == -1) {
			if (errno != EEXIST) {
				pr_perror("Failed to mkdir journal dir");
				goto out;
			}
		}

		if (strcmp("", mount_label)) {
			rc = setfilecon(journal_dir, mount_label);
			if (rc < 0) {
				pr_perror("Failed to set journal dir selinux context");
				goto out;
			}
		}

		if (makepath(cont_journal_dir, 0755) == -1) {
			if (errno != EEXIST) {
				pr_perror("Failed to mkdir container journal dir");
				goto out;
			}
		}

		/* Mount journal directory at /var/log/journal/UUID in the container */
		if (mount(journal_dir, cont_journal_dir, "bind", MS_BIND|MS_REC, NULL) == -1) {
			pr_perror("Failed to mount %s at %s", journal_dir, cont_journal_dir);
			goto out;
		}
	}

#if 0
	if (!contains_mount(config_mounts, config_mounts_len, "/sys/fs/cgroup")) {
		char cont_cgroup_dir[PATH_MAX];
		snprintf(cont_cgroup_dir, PATH_MAX, "%s/sys/fs/cgroup", rootfs);

		if (makepath(cont_cgroup_dir, 0755) == -1) {
			if (errno != EEXIST) {
				pr_perror("Failed to mkdir container cgroup dir");
				goto out;
			}
		}

		/* Mount cgroup directory at /sys/fs/cgroup in the container */
		if (mount("/sys/fs/cgroup", cont_cgroup_dir, "bind", MS_BIND|MS_REC, "ro") == -1) {
			pr_perror("Failed to mount /sys/fs/cgroup at %s", cont_cgroup_dir);
			goto out;
		}
	}
#endif
	if (!contains_mount(config_mounts, config_mounts_len, "/etc/machine-id")) {
		char mid_path[PATH_MAX];
		snprintf(mid_path, PATH_MAX, "%s/etc/machine-id", rootfs);
		fd = open(mid_path, O_CREAT|O_WRONLY, 0444);
		if (fd < 0) {
			pr_perror("Failed to open %s for writing\n", mid_path);
			goto out;
		}

		rc = dprintf(fd, "%.32s\n", id);
		if (rc < 0) {
			pr_perror("Failed to write id to %s\n", mid_path);
			goto out;
		}
	}

	ret = 0;
out:
	if (fd > -1)
		close(fd);
	if (options)
		free(options);

	return ret;
}

int poststop(const char *rootfs,
		const char *id,
		int pid,
		char **config_mounts,
		unsigned config_mounts_len)
{
	if (contains_mount(config_mounts, config_mounts_len, "/etc/machine-id")) {
		return 0;
	}

	int ret = 0;
	char mid_path[PATH_MAX];
	snprintf(mid_path, PATH_MAX, "%s/etc/machine-id", rootfs);

	if (unlink(mid_path) != 0 && (errno != ENOENT)) {
		pr_perror("Unable to remove %s", mid_path);
		ret = 1;
	}

	return ret;
}

int main(int argc, char *argv[])
{

	if (argc < 3) {
		pr_perror("Expect atleast 2 arguments");
		exit(1);
	}

	size_t rd;
	yajl_val node;
	yajl_val config_node;
	char errbuf[BUFLEN];
	char stateData[CONFIGSZ];
	char configData[CONFIGSZ];
	int ret = -1;
	FILE *fp = NULL;

	stateData[0] = 0;
	errbuf[0] = 0;

	/* Read the entire config file from stdin */
	rd = fread((void *)stateData, 1, sizeof(stateData) - 1, stdin);
	if (rd == 0 && !feof(stdin)) {
		pr_perror("error encountered on file read\n");
		return 1;
	} else if (rd >= sizeof(stateData) - 1) {
		pr_perror("config file too big\n");
		return 1;
	}

	/* Parse the state */
	node = yajl_tree_parse((const char *)stateData, errbuf, sizeof(errbuf));
	if (node == NULL) {
		pr_perror("parse_error: ");
		if (strlen(errbuf)) {
			pr_perror(" %s", errbuf);
		} else {
			pr_perror("unknown error");
		}
		pr_perror("\n");
		return 1;
	}

	/* Extract values from the state json */
	const char *root_path[] = { "root", (const char *)0 };
	yajl_val v_root = yajl_tree_get(node, root_path, yajl_t_string);
	if (!v_root) {
		pr_perror("root not found in state\n");
		goto out;
	}
	char *rootfs = YAJL_GET_STRING(v_root);

	const char *pid_path[] = { "pid", (const char *) 0 };
	yajl_val v_pid = yajl_tree_get(node, pid_path, yajl_t_number);
	if (!v_pid) {
		pr_perror("pid not found in state\n");
		goto out;
	}
	int target_pid = YAJL_GET_INTEGER(v_pid);

	const char *id_path[] = { "id", (const char *)0 };
	yajl_val v_id = yajl_tree_get(node, id_path, yajl_t_string);
	if (!v_id) {
		pr_perror("id not found in state\n");
		goto out;
	}
	char *id = YAJL_GET_STRING(v_id);

	/* Parse the config file */
	fp = fopen(argv[2], "r");
	if (fp == NULL) {
		pr_perror("Failed to open config file: %s\n", argv[2]);
		goto out;
	}
	rd = fread((void *)configData, 1, sizeof(configData) - 1, fp);
	if (rd == 0 && !feof(fp)) {
		pr_perror("error encountered on file read\n");
		goto out;
	} else if (rd >= sizeof(configData) - 1) {
		pr_perror("config file too big\n");
		goto out;
	}

	config_node = yajl_tree_parse((const char *)configData, errbuf, sizeof(errbuf));
	if (config_node == NULL) {
		pr_perror("parse_error: ");
		if (strlen(errbuf)) {
			pr_perror(" %s", errbuf);
		} else {
			pr_perror("unknown error");
		}
		pr_perror("\n");
		goto out;
	}

	/* Extract values from the config json */
	const char *mount_label_path[] = { "MountLabel", (const char *)0 };
	yajl_val v_mount = yajl_tree_get(config_node, mount_label_path, yajl_t_string);
	if (!v_mount) {
		pr_perror("MountLabel not found in config\n");
		goto out;
	}
	char *mount_label = YAJL_GET_STRING(v_mount);

	fprintf(stdout, "Mount Label parsed as: %s\n", mount_label);

	/* Extract values from the config json */
	const char *mount_points_path[] = { "MountPoints", (const char *)0 };
	yajl_val v_mps = yajl_tree_get(config_node, mount_points_path, yajl_t_object);
	if (!v_mps) {
		pr_perror("MountPoints not found in config\n");
		goto out;
	}

	char **config_mounts = YAJL_GET_OBJECT(v_mps)->keys;
	unsigned config_mounts_len = YAJL_GET_OBJECT(v_mps)->len;
	if (!strcmp("prestart", argv[1])) {
		if (prestart(rootfs, id, target_pid, mount_label, config_mounts, config_mounts_len) != 0) {
			goto out;
		}
	} else if (!strcmp("poststop", argv[1])) {
		if (poststop(rootfs, id, target_pid, config_mounts, config_mounts_len) != 0) {
			goto out;
		}
	} else {
		pr_perror("command not recognized: %s\n", argv[1]);
		goto out;
	}

	ret = 0;
out:
	yajl_tree_free(node);
	if (fp)
		fclose(fp);
	if (config_node)
		yajl_tree_free(config_node);
	return ret;
}
