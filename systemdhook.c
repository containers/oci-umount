#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sched.h>
#include <unistd.h>
#include <errno.h>
#include <linux/limits.h>
#include <selinux/selinux.h>
#include <yajl/yajl_tree.h>

#define pr_perror(fmt, ...) fprintf(stderr, "systemdhook: " fmt ": %m\n", ##__VA_ARGS__)

#define BUFLEN 1024
#define CONFIGSZ 65536

int prestart(const char *rootfs, const char *id, int pid, const char *mount_label)
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

	char journal_dir[PATH_MAX];
	snprintf(journal_dir, PATH_MAX, "/var/log/journal/%.32s", id);
	char cont_journal_dir[PATH_MAX];
	snprintf(cont_journal_dir, PATH_MAX, "%s/var/log/journal", rootfs);
	if (mkdir(journal_dir, 0755) == -1) {
		if (errno != EEXIST) {
			pr_perror("Failed to mkdir journal dir");
			goto out;
		}
	}

	if (!strcmp("", mount_label)) {
		rc = setfilecon(journal_dir, mount_label);
		if (rc < 0) {
			pr_perror("Failed to set journal dir selinux context");
			goto out;
		}
	}

	if (mkdir(cont_journal_dir, 0755) == -1) {
		if (errno != EEXIST) {
			pr_perror("Failed to mkdir container journal dir");
			goto out;
		}
	}

	/* Mount journal directory at /var/log/journal in the container */
	if (mount(journal_dir, cont_journal_dir, "bind", MS_BIND|MS_REC, NULL) == -1) {
		pr_perror("Failed to mount %s at %s", journal_dir, cont_journal_dir);
		goto out;
	}

	char run_id_path[PATH_MAX];
	snprintf(run_id_path, PATH_MAX, "/run/%s/", id);
	if (mkdir(run_id_path, 0700) == -1) {
		if (errno != EEXIST) {
			pr_perror("Failed to mkdir run id dir");
			goto out;
		}
	}

	char etc_dir_path[PATH_MAX];
	snprintf(etc_dir_path, PATH_MAX, "/run/%s/etc", id);
	if (mkdir(etc_dir_path, 0700) == -1) {
		if (errno != EEXIST) {
			pr_perror("Failed to mkdir etc dir");
			goto out;
		}
	}

	char mid_path[PATH_MAX];
	snprintf(mid_path, PATH_MAX, "/run/%s/etc/machine-id", id);
	fd = open(mid_path, O_CREAT|O_WRONLY, 0444);
	if (fd < 0) {
		fprintf(stderr, "Failed to open %s for writing\n", mid_path);
		goto out;
	}

	rc = dprintf(fd, "%.32s", id);
	if (rc < 0) {
		fprintf(stderr, "Failed to write id to %s\n", mid_path);
		goto out;
	}

	if (!strcmp("", mount_label)) {
		rc = fsetfilecon(fd, mount_label);
		if (rc < 0) {
			pr_perror("Failed to set machine-id selinux context");
			goto out;
		}
	}

	char cont_mid_path[PATH_MAX];
	snprintf(cont_mid_path, PATH_MAX, "%s/etc/machine-id", rootfs);
	mfd = open(cont_mid_path, O_CREAT|O_WRONLY, 0444);
	if (mfd < 0) {
		pr_perror("Failed to open: %s", cont_mid_path);
		goto out;
	}

	if (mount(mid_path, cont_mid_path, "bind", MS_BIND|MS_REC, "ro") == -1) {
		pr_perror("Failed to mount %s at %s", mid_path, cont_mid_path);
		goto out;
	}

	ret = 0;
out:
	if (fd > -1)
		close(fd);
	if (mfd > -1)
		close(mfd);
	if (options)
		free(options);

	return ret;
}

int poststop(const char *roofs, const char *id, int pid)
{
	int ret = 0;
	char run_id_path[PATH_MAX];
	snprintf(run_id_path, PATH_MAX, "/run/%s/", id);
	char etc_dir_path[PATH_MAX];
	snprintf(etc_dir_path, PATH_MAX, "/run/%s/etc", id);
	char mid_path[PATH_MAX];
	snprintf(mid_path, PATH_MAX, "/run/%s/etc/machine-id", id);

	if (unlink(mid_path) != 0) {
		pr_perror("Unable to remove %s", mid_path);
		ret = 1;
	}

	if (rmdir(etc_dir_path) != 0) {
		pr_perror("Unable to remove %s", etc_dir_path);
		ret = 1;
	}

	if (rmdir(run_id_path) != 0) {
		pr_perror("Unable to remove %s", run_id_path);
		ret = 1;
	}

	return ret;
}

int main(int argc, char *argv[])
{

	if (argc < 3) {
		fprintf(stderr, "Expect atleast 2 arguments");
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
		fprintf(stderr, "error encountered on file read\n");
		return 1;
	} else if (rd >= sizeof(stateData) - 1) {
		fprintf(stderr, "config file too big\n");
		return 1;
	}

	/* Parse the state */
	node = yajl_tree_parse((const char *)stateData, errbuf, sizeof(errbuf));
	if (node == NULL) {
		fprintf(stderr, "parse_error: ");
		if (strlen(errbuf)) {
		       	fprintf(stderr, " %s", errbuf);
		} else {
			fprintf(stderr, "unknown error");
		}
		fprintf(stderr, "\n");
		return 1;
	}

	/* Extract values from the state json */
	const char *root_path[] = { "root", (const char *)0 };
	yajl_val v_root = yajl_tree_get(node, root_path, yajl_t_string);
	if (!v_root) {
		fprintf(stderr, "root not found in state\n");
		goto out;
	}
	char *rootfs = YAJL_GET_STRING(v_root);

	const char *pid_path[] = { "pid", (const char *) 0 };
	yajl_val v_pid = yajl_tree_get(node, pid_path, yajl_t_number);
	if (!v_pid) {
		fprintf(stderr, "pid not found in state\n");
		goto out;
	}
	int target_pid = YAJL_GET_INTEGER(v_pid);

	const char *id_path[] = { "id", (const char *)0 };
	yajl_val v_id = yajl_tree_get(node, id_path, yajl_t_string);
	if (!v_id) {
		fprintf(stderr, "id not found in state\n");
		goto out;
	}
	char *id = YAJL_GET_STRING(v_id);

	/* Parse the config file */
	fp = fopen(argv[2], "r");
	if (fp == NULL) {
		fprintf(stderr, "Failed to open config file: %s\n", argv[2]);
		goto out;
	}
	rd = fread((void *)configData, 1, sizeof(configData) - 1, fp);
	if (rd == 0 && !feof(fp)) {
		fprintf(stderr, "error encountered on file read\n");
		goto out;
	} else if (rd >= sizeof(configData) - 1) {
		fprintf(stderr, "config file too big\n");
		goto out;
	}

	config_node = yajl_tree_parse((const char *)configData, errbuf, sizeof(errbuf));
	if (config_node == NULL) {
		fprintf(stderr, "parse_error: ");
		if (strlen(errbuf)) {
			fprintf(stderr, " %s", errbuf);
		} else {
			fprintf(stderr, "unknown error");
		}
		fprintf(stderr, "\n");
		goto out;
	}

	/* Extract values from the config json */
	const char *mount_label_path[] = { "MountLabel", (const char *)0 };
	yajl_val v_mount = yajl_tree_get(config_node, mount_label_path, yajl_t_string);
	if (!v_mount) {
		fprintf(stderr, "MountLabel not found in config\n");
		goto out;
	}
	char *mount_label = YAJL_GET_STRING(v_mount);

	fprintf(stdout, "Mount Label parsed as: %s", mount_label);

	if (!strncmp("prestart", argv[1], sizeof("prestart"))) {
		if (prestart(rootfs, id, target_pid, mount_label) != 0) {
			goto out;
		}
	} else if (!strncmp("poststop", argv[1], sizeof("poststop"))) {
		if (poststop(rootfs, id, target_pid) != 0) {
			goto out;
		}
	} else {
		fprintf(stderr, "command not recognized: %s\n", argv[1]);
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
