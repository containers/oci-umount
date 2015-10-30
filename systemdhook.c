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
#include <selinux/context.h>

#include "yajl/yajl_tree.h"

#define pr_perror(fmt, ...) fprintf(stderr, "systemdhook: " fmt ": %m\n", ##__VA_ARGS__)

#define BUFLEN 1024
#define CONFIGSZ 65536

static char *get_file_context(const char *filename) {
	FILE *file = fopen(filename, "r");
	char line [1000];
	char key [1000];
	char value [1000];

	if (file != NULL) {
		while(fgets(line, sizeof(line), file)!= NULL) /* read a line from a file */ {
		sscanf(line, "%[^= ] = \"%[^\n\"]\"", key, value);
		if (strcmp(key,"file") == 0) {
			fclose(file);
			return strdup(value);
		}
		}

		fclose(file);
	}
	else {
		perror(filename); //print the error message on stderr.
	}

	return NULL;
}

char *generate_mount_context(int pid) {
	security_context_t scon, tcon;
	char *mountcon;

	if (is_selinux_enabled() > 0) {
		context_t con, con1;
		const char *level;
		int i = getpidcon(pid, &scon);
		if (i < 0) {
			perror("Failed to pidcon");
			return NULL;
		}
		con = context_new(scon);
		level = context_range_get(con);
		tcon = get_file_context(selinux_lxc_contexts_path());
		if (tcon == NULL) {
			perror("Failed to get lxc_context");
			return NULL;
		}
		con1 = context_new(tcon);
		context_range_set(con1, level);
		i = asprintf(&mountcon, "context=\"%s\"", context_str(con1));
		if (i < 0) {
			perror("Failed to allocate memory");
			return NULL;
		}
		context_free(con);
		context_free(con1);
		freecon(scon);
		freecon(tcon);
		return mountcon;
	}
	return NULL;
}

int prestart(const char *rootfs, const char *id, int pid)
{
	int ret = 1;
	char *mount_context = NULL;
	int mfd = -1;
	int fd = -1;
	int rc = -1;
	FILE *fp = NULL;
	char *context = NULL;

	mount_context = generate_mount_context(pid);
	if (mount_context == NULL) {
		pr_perror("Failed to generate selinux context for /run");
		goto out;
	}

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

	rc = asprintf(&context, "mode=755,size=65536k,%s", mount_context);
	if (rc < 0) {
		pr_perror("Failed to allocate memory for context");
		goto out;
	}

	/* Mount tmpfs at /run for systemd */
	if (mount("tmpfs", run_dir, "tmpfs", MS_NODEV|MS_NOSUID|MS_NOEXEC, context) == -1) {
		pr_perror("Failed to mount tmpfs at /run");
		goto out;
	}

	char journal_dir[PATH_MAX];
	snprintf(journal_dir, PATH_MAX, "/var/log/journal/%s", id);
	char cont_journal_dir[PATH_MAX];
	snprintf(cont_journal_dir, PATH_MAX, "%s/var/log/journal", rootfs);
	if (mkdir(journal_dir, 0666) == -1) {
		if (errno != EEXIST) {
			pr_perror("Failed to mkdir journal dir");
			goto out;
		}
	}

	if (mkdir(cont_journal_dir, 0666) == -1) {
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

	char tmp_id_path[PATH_MAX];
	snprintf(tmp_id_path, PATH_MAX, "/tmp/%s/", id);
	if (mkdir(tmp_id_path, 0666) == -1) {
		if (errno != EEXIST) {
			pr_perror("Failed to mkdir tmp id dir");
			goto out;
		}
	}

	char etc_dir_path[PATH_MAX];
	snprintf(etc_dir_path, PATH_MAX, "/tmp/%s/etc", id);
	if (mkdir(etc_dir_path, 0666) == -1) {
		if (errno != EEXIST) {
			pr_perror("Failed to mkdir etc dir");
			goto out;
		}
	}

	char mid_path[PATH_MAX];
	snprintf(mid_path, PATH_MAX, "/tmp/%s/etc/machine-id", id);
	fp = fopen(mid_path, "w");
	if (fp == NULL) {
		fprintf(stderr, "Failed to open %s for writing\n", mid_path);
		goto out;
	}

	rc = fprintf(fp, "%s", id);
	if (rc < 0) {
		fprintf(stderr, "Failed to write id to %s\n", mid_path);
		goto out;
	}

	char cont_mid_path[PATH_MAX];
	snprintf(cont_mid_path, PATH_MAX, "%s/etc/machine-id", rootfs);
	mfd = open(cont_mid_path, O_CREAT|O_WRONLY, 0666);
	if (mfd < 0) {
		pr_perror("Failed to open: %s", cont_mid_path);
		goto out;
	}

	if (mount(mid_path, cont_mid_path, "bind", MS_BIND|MS_REC, NULL) == -1) {
		pr_perror("Failed to mount %s at %s", mid_path, cont_mid_path);
		goto out;
	}

	ret = 0;
out:
	if (mount_context)
		free(mount_context);
	if (fd > 0)
		close(fd);
	if (fp)
		fclose(fp);
	if (mfd > 0)
		close(mfd);
	if (context)
		free(context);

	return ret;
}

int poststop(const char *roofs, const char *id, int pid)
{
	int ret = 0;
	char tmp_id_path[PATH_MAX];
	snprintf(tmp_id_path, PATH_MAX, "/tmp/%s/", id);
	char etc_dir_path[PATH_MAX];
	snprintf(etc_dir_path, PATH_MAX, "/tmp/%s/etc", id);
	char mid_path[PATH_MAX];
	snprintf(mid_path, PATH_MAX, "/tmp/%s/etc/machine-id", id);

	if (unlink(mid_path) != 0) {
		pr_perror("Unable to remove %s", mid_path);
		ret = 1;
	}

	if (rmdir(etc_dir_path) != 0) {
		pr_perror("Unable to remove %s", etc_dir_path);
		ret = 1;
	}

	if (rmdir(tmp_id_path) != 0) {
		pr_perror("Unable to remove %s", tmp_id_path);
		ret = 1;
	}

	return ret;
}

int main(int argc, char *argv[])
{

	if (argc < 2) {
		fprintf(stderr, "Expect atleast 2 arguments");
		exit(1);
	}

	size_t rd;
	yajl_val node;
	char errbuf[BUFLEN];
	char fileData[CONFIGSZ];
	int ret = -1;

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
		goto out;
	}

	const char *pid_path[] = { "pid", (const char *) 0 };
	yajl_val v_pid = yajl_tree_get(node, pid_path, yajl_t_number);
	int target_pid = YAJL_GET_INTEGER(v_pid);
	if (!v_pid) {
		fprintf(stderr, "pid not found in state\n");
		goto out;
	}

	const char *id_path[] = { "id", (const char *)0 };
	yajl_val v_id = yajl_tree_get(node, id_path, yajl_t_string);
	char *id = YAJL_GET_STRING(v_id);
	if (!v_id) {
		fprintf(stderr, "id not found in state\n");
		goto out;
	}


	if (!strncmp("prestart", argv[1], sizeof("prestart"))) {
		if (prestart(rootfs, id, target_pid) != 0) {
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
	return ret;
}
