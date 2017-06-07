#define _GNU_SOURCE
#include <stdio.h>
#include <libgen.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/mount.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <dirent.h>
#include <fcntl.h>
#include <sched.h>
#include <unistd.h>
#include <errno.h>
#include <inttypes.h>
#include <linux/limits.h>
#include <selinux/selinux.h>
#include <yajl/yajl_tree.h>

#include "config.h"

#define _cleanup_(x) __attribute__((cleanup(x)))

#define MOUNTCONF "/etc/oci-umount.conf"
#define MOUNTINFO_PATH "/proc/self/mountinfo"
#define MAX_UMOUNTS	128	/* Maximum number of unmounts */

/* Basic mount info. For now we need only destination */
struct mount_info {
	char *destination;
};

/* Basic config mount info */
struct config_mount_info {
	char *source;
	char *destination;
};

static inline void freep(void *p) {
	free(*(void**) p);
}

static inline void closep(int *fd) {
	if (*fd >= 0)
		close(*fd);
	*fd = -1;
}

static inline void fclosep(FILE **fp) {
	if (*fp)
		fclose(*fp);
	*fp = NULL;
}

static inline void free_mnt_info(struct mount_info **p) {
	unsigned i;
	struct mount_info *mi = *p;

	if (mi == NULL)
		return;

	for (i = 0; mi[i].destination; i++) {
		free(mi[i].destination);
	}
	free(mi);
}

/* Free an array of char pointers */
static inline void free_cptr_array(char ***p) {
	unsigned i;
	char **ptr = *p;

	if (ptr == NULL)
		return;

	for (i = 0; ptr[i]; i++) {
		free(ptr[i]);
	}
	free(ptr);
}

static inline void free_config_mounts(struct config_mount_info **p) {
	unsigned i;
	struct config_mount_info *cm = *p;

	if (cm == NULL)
		return;

	for (i = 0; cm[i].destination || cm[i].source; i++) {
		if (cm[i].destination)
			free(cm[i].destination);
		if (cm[i].source)
			free(cm[i].source);
	}
	free(cm);
}

#define _cleanup_free_ _cleanup_(freep)
#define _cleanup_close_ _cleanup_(closep)
#define _cleanup_fclose_ _cleanup_(fclosep)
#define _cleanup_mnt_info_ _cleanup_(free_mnt_info)
#define _cleanup_cptr_array_ _cleanup_(free_cptr_array)
#define _cleanup_config_mounts_ _cleanup_(free_config_mounts)

#define DEFINE_CLEANUP_FUNC(type, func)                         \
	static inline void func##p(type *p) {                   \
		if (*p)                                         \
			func(*p);                               \
	}                                                       \

DEFINE_CLEANUP_FUNC(yajl_val, yajl_tree_free)

#define pr_perror(fmt, ...) syslog(LOG_ERR, "umounthook <error>: " fmt ": %m\n", ##__VA_ARGS__)
#define pr_pinfo(fmt, ...) syslog(LOG_INFO, "umounthook <info>: " fmt "\n", ##__VA_ARGS__)
#define pr_pdebug(fmt, ...) syslog(LOG_DEBUG, "umounthook <debug>: " fmt "\n", ##__VA_ARGS__)

#define BUFLEN 1024
#define CHUNKSIZE 4096

static void *grow_mountinfo_table(void *curr_table, size_t curr_sz, size_t new_sz) {
	void *table;

	table = realloc(curr_table, new_sz);
	if (!table)
		return NULL;

	/* Zero newly allocated area */
	memset(table + curr_sz, 0, (new_sz - curr_sz));
	return table;
}


/* Get mount destination given the source, from config data */
static char *get_config_mount_dest(const struct config_mount_info *config_mounts, unsigned len, char *source)
{
	for (unsigned i = 0; i < len; i++) {
		if (!strcmp(source, config_mounts[i].source)) {
			return config_mounts[i].destination;
		}
	}
	return NULL;
}

static int parse_mountinfo(struct mount_info **info, size_t *sz)
{
	_cleanup_fclose_ FILE *fp;
	_cleanup_mnt_info_ struct mount_info *mnt_table = NULL;
	struct mount_info *mnt_table_temp;
	int nr_elem = 64;
	int elem_sz = sizeof(struct mount_info);
	/*
	 * table size bytes also keeps track of last zero element while
	 * nr_elem does not
	 */
	size_t table_sz_bytes = (nr_elem + 1) * elem_sz;
	_cleanup_free_ char *line = NULL;
	size_t len = 0;
	int table_idx = 0;

	fp = fopen(MOUNTINFO_PATH, "r");
	if (!fp) {
		pr_perror("Failed to open %s\n", MOUNTINFO_PATH);
		return -1;
	}

	/*
	 * Alaways allocate one member extra at the end and keep it zero so
	 * that cleanup function can find the end of array.
	 */
	mnt_table = (struct mount_info *)realloc(NULL, table_sz_bytes);
	if (!mnt_table) {
		pr_perror("Failed to allocate memory for mount tabel\n");
		return -1;
	}

	memset(mnt_table, 0, table_sz_bytes);

	while ((getline(&line, &len, fp)) != -1) {
		char *token, *str = line, *dest;
		int token_idx = 0;

		while ((token = strtok(str, " ")) != NULL) {
			str = NULL;
			token_idx++;
			if (token_idx != 5)
			       continue;

			dest = strdup(token);
			if (!dest) {
				pr_perror("strdup() failed\n");
				return -1;
			}

			mnt_table[table_idx++].destination = dest;
			if (table_idx == nr_elem) {
				int new_sz_bytes = table_sz_bytes + elem_sz * 64;
				mnt_table_temp = grow_mountinfo_table(mnt_table, table_sz_bytes, new_sz_bytes);
				if (!mnt_table_temp) {
					pr_perror("Failed to realloc mountinfo table\n");
					return -1;
				}
				mnt_table = mnt_table_temp;
				table_sz_bytes = new_sz_bytes;
				nr_elem += 64;
			}
		}
	}

	*info = mnt_table;
	*sz = table_idx;
	/* Make sure cleanup function does not free up this table now */
	mnt_table = NULL;
	return 0;
}

static bool is_mounted(char *path, struct mount_info *mnt_table, size_t table_sz) {
	size_t i;

	for (i = 0; i < table_sz; i++) {
		if (!strcmp(mnt_table[i].destination, path))
			return true;
	}
	return false;
}

/* Returns <0 on error, 0 when no mapping exists and 1 when mapping exists */
static int map_mount_host_to_container(const struct config_mount_info *config_mounts, unsigned config_mounts_len, char *host_mnt, char *cont_mnt, unsigned max_dest_len)
{
	char *str, *rem_host_mnt;
	_cleanup_free_ char *host_mnt_dup = NULL;
	char *destination = NULL;
	int dest_len;

	host_mnt_dup = strdup(host_mnt);
	if (!host_mnt_dup) {
		pr_perror("strdup(%s) failed.\n", host_mnt);
		return -1;
	}

	str = host_mnt_dup;
	do {
		destination = get_config_mount_dest(config_mounts, config_mounts_len, str);
		if (destination)
			break;
		if (!strcmp(str, "/"))
			break;
	} while ((str = dirname(str)));

	if (!destination)
		return 0;

	dest_len = strlen(destination);
	rem_host_mnt = host_mnt + strlen(str);

	if (dest_len + strlen(rem_host_mnt)  + 1 > max_dest_len - 1) {
		pr_perror("Not enough space to store mapped string\n");
		return -1;
	}

	*cont_mnt = '\0';
	strcat(cont_mnt, destination);
	if (rem_host_mnt[0] != '\0') {
		if (destination[dest_len - 1] != '/' && rem_host_mnt[0] != '/')
			strcat(cont_mnt, "/");
		strcat(cont_mnt, rem_host_mnt);
	}

	pr_pinfo("mapped host_mnt=%s to cont_mnt=%s\n", host_mnt, cont_mnt);
	return 1;
}


static int prestart(const char *rootfs,
		int pid,
		const struct config_mount_info *config_mounts,
		unsigned config_mounts_len)
{
	pr_pinfo("prestart %s", rootfs);
	_cleanup_close_  int fd = -1;
	_cleanup_free_   char *options = NULL;

	size_t mnt_table_sz;
	_cleanup_mnt_info_ struct mount_info *mnt_table = NULL;

	char process_mnt_ns_fd[PATH_MAX];
	char umount_path[PATH_MAX];
	_cleanup_fclose_ FILE *fp = NULL;
	_cleanup_cptr_array_ char **mounts_on_host = NULL;
	int nr_umounts = 0;
	_cleanup_free_ char *line = NULL;
	char *real_path;
	size_t len = 0;
	ssize_t read;
	int i, ret;

	/* Allocate one extra element and keep it zero for cleanup function */
	mounts_on_host = malloc((MAX_UMOUNTS + 1) * sizeof(char *));
	if (!mounts_on_host) {
		pr_perror("Failing hook run. Unable to malloc memory for mounts_on_host table\n");
		return EXIT_FAILURE;
	}
	memset((void *)mounts_on_host, 0, (MAX_UMOUNTS + 1) * sizeof(char *));

	/* Parse oci-umounts.conf file, canonicalize path names and skip
	 * paths which are not a mountpoint on host */
	fp = fopen(MOUNTCONF, "r");
	if (fp == NULL) {
		pr_perror("Failing hook run. Unable to open required config file: %s", MOUNTCONF);
		return EXIT_FAILURE;
	}

	while ((read = getline(&line, &len, fp)) != -1) {
		/* Get rid of newline character at the end */
		line[read - 1] ='\0';

		if (nr_umounts == MAX_UMOUNTS) {
			pr_perror("Failing hook run. Exceeded maximum number of supported unmounts is %d\n", MAX_UMOUNTS);
			return EXIT_FAILURE;
		}

		real_path = realpath(line, NULL);
		if (!real_path) {
			pr_pinfo("Failed to canonicalize path [%s]. Skipping.", line);
			continue;
		}

		mounts_on_host[nr_umounts++] = real_path;
	}

	snprintf(process_mnt_ns_fd, PATH_MAX, "/proc/%d/ns/mnt", pid);

	fd = open(process_mnt_ns_fd, O_RDONLY);
	if (fd < 0) {
		pr_perror("Failing hook run. Unable to open mnt namespace fd %s", process_mnt_ns_fd);
		return EXIT_FAILURE;
	}

	/* Join the mount namespace of the target process */
	if (setns(fd, 0) == -1) {
		pr_perror("Failing hook run. Failed to setns to %s", process_mnt_ns_fd);
		return EXIT_FAILURE;
	}

	/* Switch to the root directory */
	if (chdir("/") == -1) {
		pr_perror("Failing hook run. Unable to chdir");
		return EXIT_FAILURE;
	}

	/* Parse mount table */
	ret = parse_mountinfo(&mnt_table, &mnt_table_sz);
	if (ret < 0) {
		pr_perror("Failing hook run. Unable to parse mountinfo table\n");
		return EXIT_FAILURE;
	}

	for (i = 0; i < nr_umounts; i++) {
		char mapped_path[PATH_MAX];

		ret = map_mount_host_to_container(config_mounts, config_mounts_len, mounts_on_host[i], mapped_path, PATH_MAX);
		if (ret < 0) {
			pr_perror("Error while trying to map mount [%s] from host to conatiner. Skipping.\n", mounts_on_host[i]);
			continue;
		}

		if (!ret) {
			pr_pinfo("Could not find mapping for mount [%s] from host to conatiner. Skipping.\n", mounts_on_host[i]);
			continue;
		}

		snprintf(umount_path, PATH_MAX, "%s%s", rootfs, mapped_path);

		if (!is_mounted((char *)umount_path, mnt_table, mnt_table_sz)) {
			pr_pinfo("[%s] is not a mountpoint. Skipping.", umount_path);
			continue;
		}
		ret = umount2(umount_path, MNT_DETACH);
		if (ret < 0) {
			pr_perror("Failing hook run. Unable to umount: [%s]", umount_path);
			return EXIT_FAILURE;
		}

		pr_pinfo("Unmounted %s \n", umount_path);
	}
	return 0;
}

/*
 * Read the entire content of stream pointed to by 'from' into a buffer in memory.
 * Return a pointer to the resulting NULL-terminated string.
 */
char *getJSONstring(FILE *from, size_t chunksize, char *msg)
{
	struct stat stat_buf;
	char *err = NULL, *JSONstring = NULL;
	size_t nbytes, bufsize;

	if (fstat(fileno(from), &stat_buf) == -1) {
		err = "fstat failed";
		goto fail;
	}

	if (S_ISREG(stat_buf.st_mode)) {
		/*
		 * If 'from' is a regular file, allocate a buffer based
		 * on the file size and read the entire content with a
		 * single fread() call.
		 */
		if (stat_buf.st_size == 0) {
			err = "is empty";
			goto fail;
		}

		bufsize = (size_t)stat_buf.st_size;

		JSONstring = (char *)malloc(bufsize + 1);
		if (JSONstring == NULL) {
			err = "failed to allocate buffer";
			goto fail;
		}

		nbytes = fread((void *)JSONstring, 1, (size_t)bufsize, from);
		if (nbytes != (size_t)bufsize) {
			err = "error encountered on read";
			goto fail;
		}
	} else {
		/*
		 * If 'from' is not a regular file, call fread() iteratively
		 * to read sections of 'chunksize' bytes until EOF is reached.
		 * Call realloc() during each iteration to expand the buffer
		 * as needed.
		 */
		bufsize = 0;

		for (;;) {
			JSONstring = (char *)realloc((void *)JSONstring, bufsize + chunksize);
			if (JSONstring == NULL) {
				err = "failed to allocate buffer";
				goto fail;
			}

			nbytes = fread((void *)&JSONstring[bufsize], 1, (size_t)chunksize, from);
			bufsize += nbytes;

			if (nbytes != (size_t)chunksize) {
				if (ferror(from)) {
					err = "error encountered on read";
					goto fail;
				}
				if (feof(from))
					break;
			}
		}

		if (bufsize == 0) {
			err = "is empty";
			goto fail;
		}

		JSONstring = (char *)realloc((void *)JSONstring, bufsize + 1);
		if (JSONstring == NULL) {
			err = "failed to allocate buffer";
			goto fail;
		}
	}

	/* make sure the string is NULL-terminated */
	JSONstring[bufsize] = 0;
	return JSONstring;
fail:
	free(JSONstring);
	pr_perror("%s: %s", msg, err);
	return NULL;
}

static int parseBundle(yajl_val *node_ptr, struct config_mount_info **mounts, size_t *mounts_len)
{
	yajl_val node = *node_ptr;
	char config_file_name[PATH_MAX];
	char errbuf[BUFLEN];
	char *configData;
	_cleanup_(yajl_tree_freep) yajl_val config_node = NULL;
	_cleanup_config_mounts_ struct config_mount_info *config_mounts = NULL;
	unsigned config_mounts_len = 0;
	_cleanup_fclose_ FILE *fp = NULL;

	/* 'bundlePath' must be specified for the OCI hooks, and from there we read the configuration file */
	const char *bundle_path[] = { "bundlePath", (const char *)0 };
	yajl_val v_bundle_path = yajl_tree_get(node, bundle_path, yajl_t_string);
	if (v_bundle_path) {
		snprintf(config_file_name, PATH_MAX, "%s/config.json", YAJL_GET_STRING(v_bundle_path));
		fp = fopen(config_file_name, "r");
	} else {
		char msg[] = "bundlePath not found in state";
		snprintf(config_file_name, PATH_MAX, "%s", msg);
	}

	if (fp == NULL) {
		pr_perror("Failing hook run. Unable to open config file: %s", config_file_name);
		return EXIT_FAILURE;
	}

	/* Read the entire config file */
	snprintf(errbuf, BUFLEN, "failed to read config data from %s", config_file_name);
	configData = getJSONstring(fp, (size_t)CHUNKSIZE, errbuf);
	if (configData == NULL)
		return EXIT_FAILURE;

	/* Parse the config file */
	memset(errbuf, 0, BUFLEN);
	config_node = yajl_tree_parse((const char *)configData, errbuf, sizeof(errbuf));
	if (config_node == NULL) {
		pr_perror("Failing hook run. parse_error: ");
		if (strlen(errbuf)) {
			pr_perror(" %s", errbuf);
		} else {
			pr_perror("unknown error");
		}
		return EXIT_FAILURE;
	}

	/* Extract values from the config json */
	const char *mount_points_path[] = {"mounts", (const char *)0 };
	yajl_val v_mounts = yajl_tree_get(config_node, mount_points_path, yajl_t_array);
	if (!v_mounts) {
		pr_perror("Failing hook run. mounts not found in config");
		return EXIT_FAILURE;
	}

	config_mounts_len = YAJL_GET_ARRAY(v_mounts)->len;
	/* Allocate one extra element which will be set to 0 and be used as
	 * end of array in free function */
	config_mounts = malloc(sizeof(struct config_mount_info) * (config_mounts_len + 1));
	if (!config_mounts) {
		pr_perror("Failing hook run. error malloc'ing");
		return EXIT_FAILURE;
	}

	memset(config_mounts, 0, sizeof(struct config_mount_info) * (config_mounts_len + 1));

	for (unsigned int i = 0; i < config_mounts_len; i++) {
		yajl_val v_mounts_values = YAJL_GET_ARRAY(v_mounts)->values[i];

		const char *destination_path[] = {"destination", (const char *)0 };
		const char *source_path[] = {"source", (const char *)0 };

		yajl_val v_destination = yajl_tree_get(v_mounts_values, destination_path, yajl_t_string);
		if (!v_destination) {
			pr_perror("Failing hook run. cannot find mount destination");
			return EXIT_FAILURE;
		}
		config_mounts[i].destination = strdup(YAJL_GET_STRING(v_destination));
		if (!config_mounts[i].destination) {
			pr_perror("Failing hook run. strdup() failed.\n");
			return EXIT_FAILURE;
		}

		yajl_val v_source = yajl_tree_get(v_mounts_values, source_path, yajl_t_string);
		if (!v_source) {
			pr_perror("Failing hook run. Cannot find mount source");
			return EXIT_FAILURE;
		}
		config_mounts[i].source = strdup(YAJL_GET_STRING(v_source));
		if (!config_mounts[i].source) {
			pr_perror("Failing hook run. strdup() failed.\n");
			return EXIT_FAILURE;
		}
	}

	*mounts = config_mounts;
	*mounts_len = config_mounts_len;
	/* set it NULL so that gcc cleanup function does not try to free this */
	config_mounts = NULL;

	return 0;
}

int main(int argc, char *argv[])
{
	_cleanup_(yajl_tree_freep) yajl_val node = NULL;
	_cleanup_(yajl_tree_freep) yajl_val config_node = NULL;
	char errbuf[BUFLEN];
	char *stateData;
	_cleanup_fclose_ FILE *fp = NULL;
	int ret;
	_cleanup_config_mounts_ struct config_mount_info *config_mounts = NULL;
	size_t config_mounts_len = 0;

	/* Read the entire state from stdin */
	snprintf(errbuf, BUFLEN, "failed to read state data from standard input");
	stateData = getJSONstring(stdin, (size_t)CHUNKSIZE, errbuf);
	if (stateData == NULL)
		return EXIT_FAILURE;

	/* Parse the state */
	memset(errbuf, 0, BUFLEN);
	node = yajl_tree_parse((const char *)stateData, errbuf, sizeof(errbuf));
	if (node == NULL) {
		pr_perror("Failing hook run. parse_error: ");
		if (strlen(errbuf)) {
			pr_perror(" %s", errbuf);
		} else {
			pr_perror("unknown error");
		}
		return EXIT_FAILURE;
	}

	/* Extract values from the state json */
	const char *root_path[] = { "root", (const char *)0 };
	yajl_val v_root = yajl_tree_get(node, root_path, yajl_t_string);
	if (!v_root) {
		pr_perror("Failing hook run. root not found in state");
		return EXIT_FAILURE;
	}
	char *rootfs = YAJL_GET_STRING(v_root);

	const char *pid_path[] = { "pid", (const char *) 0 };
	yajl_val v_pid = yajl_tree_get(node, pid_path, yajl_t_number);
	if (!v_pid) {
		pr_perror("Failing hook run. pid not found in state");
		return EXIT_FAILURE;
	}
	int target_pid = YAJL_GET_INTEGER(v_pid);

	/* OCI hooks set target_pid to 0 on poststop, as the container process already
	   exited.  If target_pid is bigger than 0 then it is the prestart hook.  */
	if ((argc > 2 && !strcmp("prestart", argv[1])) || target_pid) {
		ret = parseBundle(&node, &config_mounts, &config_mounts_len);
		if (ret < 0)
			return EXIT_FAILURE;

		if (prestart(rootfs, target_pid, config_mounts, config_mounts_len) != 0) {
			return EXIT_FAILURE;
		}
	} else if ((argc > 2 && !strcmp("poststop", argv[1])) || (target_pid == 0)) {
		return EXIT_SUCCESS;
	} else {
		pr_perror("Failing hook run. command not recognized: %s", argv[1]);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
