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

#include "yajl/yajl_tree.h"

#define pr_perror(fmt, ...) fprintf(stderr, "systemdhook: " fmt ": %m\n", ##__VA_ARGS__)

#define BUFLEN 1024
#define CONFIGSZ 65536

int main(int argc, char *argv[])
{
	size_t rd;
	yajl_val node;
	char errbuf[BUFLEN];
	char fileData[CONFIGSZ];

	fileData[0] = 0;
	errbuf[0] = 0;

	/* Read the entire config file from stdin */
	rd = fread((void *)fileData, 1, sizeof(fileData) - 1, stdin);
	if (rd == 0 && !feof(stdin)) {
		fprintf(stderr, "error encountered on file read\n");
		return 1;
	} else if (rd >= sizeof(fileData) - 1) {
		fprintf(stderr, "config file too big\n");
		return 1;
	}

	/* Parse the config */
	node = yajl_tree_parse((const char *)fileData, errbuf, sizeof(errbuf));
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
	char *rootfs = YAJL_GET_STRING(v_root);
	if (!v_root) {
		fprintf(stderr, "root not found in state\n");
		return 1;
	}

	const char *pid_path[] = { "pid", (const char *) 0 };
	yajl_val v_pid = yajl_tree_get(node, pid_path, yajl_t_number);
	int target_pid = YAJL_GET_INTEGER(v_pid);
	if (!v_pid) {
		fprintf(stderr, "pid not found in state\n");
		return 1;
	}

	const char *id_path[] = { "id", (const char *)0 };
	yajl_val v_id = yajl_tree_get(node, id_path, yajl_t_string);
	char *id = YAJL_GET_STRING(v_id);
	if (!v_id) {
		fprintf(stderr, "id not found in state\n");
		return 1;
	}
	
	char process_mnt_ns_fd[BUFLEN];
	snprintf(process_mnt_ns_fd, BUFLEN - 1, "/proc/%d/ns/mnt", target_pid);	
	int fd = open(process_mnt_ns_fd, O_RDONLY);
	if (-1 == fd) {
		pr_perror("Failed to open mnt namespace fd %s", process_mnt_ns_fd);
		exit(1);
	}

	/* Join the mount namespace of the target process */
	if (setns(fd, 0) == -1) {
		pr_perror("Failed to setns to %s", process_mnt_ns_fd);
		exit(1);
	}

	/* Switch to the root directory */
	if (chdir("/") == -1) {
		pr_perror("Failed to chdir");
		exit(1);
	}

	char run_dir[PATH_MAX];
	snprintf(run_dir, PATH_MAX, "%s/run", rootfs);

	/* Create the /run directory */
	if (mkdir(run_dir, 0755) == -1) {
		if (errno != EEXIST) {
			pr_perror("Failed to mkdir");
			exit(1);
		}
	}
			
	/* Mount tmpfs at /run for systemd */
	if (mount("tmpfs", run_dir, "tmpfs", MS_NODEV|MS_NOSUID|MS_NOEXEC, "mode=755,size=65536k") == -1) {
		pr_perror("Failed to mount tmpfs at /run");
		exit(1);
	}
		
	yajl_tree_free(node);
	return EXIT_SUCCESS;
}
