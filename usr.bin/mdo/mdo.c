/*-
 * Copyright(c) 2024 Baptiste Daroussin <bapt@FreeBSD.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/limits.h>
#include <sys/types.h>
#include <sys/ucred.h>

#include <err.h>
#include <grp.h>
#include <paths.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void
usage(void)
{
	fprintf(stderr, "usage: mdo [-u username] [-i] [--] [command [args]]\n");
	exit(EXIT_FAILURE);
}

int
main(int argc, char **argv)
{
	struct passwd *pw = NULL;
	const char *username = "root";
	const char *primary_group;
	const char *supp_groups_str;
	struct setcred wcred = SETCRED_INITIALIZER;
	u_int setcred_flags = 0;
	bool uidonly = false;
	int ch;

	gid_t *supp_groups;
	size_t supp_count = 0;
	gid_t gid = -1;
	bool override_gid = false;

	while ((ch = getopt(argc, argv, "u:ig:G:")) != -1) {
		switch (ch) {
		case 'u':
			username = optarg;
			break;
		case 'i':
			uidonly = true;
			break;
		case 'g':
			primary_group = optarg;
			break;
		case 'G':
			supp_groups_str = optarg;
			break;
		default:
			usage();
		}
	}

	if (uidonly && (primary_group || supp_groups_str))
		errx(EXIT_FAILURE, "-i cannot be used with -g and -G");

	argc -= optind;
	argv += optind;

	//uid_t target_uid = getuid();
	gid_t target_gid = getgid();

	if (username) {
		if ((pw = getpwnam(username)) == NULL) {
			if (strspn(username, "0123456789") == strlen(username)) {
				const char *errp = NULL;
				uid_t uid = strtonum(username, 0, UID_MAX, &errp);
				if (errp != NULL)
					err(EXIT_FAILURE, "invalid user ID '%s'",
						username);
				pw = getpwuid(uid);
			}
			if (pw == NULL)
				err(EXIT_FAILURE, "invalid username '%s'", username);
		}
		//target_uid = pw->pw_uid;
		target_gid = pw->pw_gid;
	}

	wcred.sc_uid = wcred.sc_ruid = wcred.sc_svuid = pw->pw_uid;
	setcred_flags |= SETCREDF_UID | SETCREDF_RUID | SETCREDF_SVUID;

	if (primary_group) {
		struct group *gr = getgrnam(primary_group);
		if (gr)
			gid = gr->gr_gid;
		else {
			const char *errp = NULL;
			gid = strtonum(primary_group, 0, GID_MAX, &errp);
			if (errp != NULL)
				err(EXIT_FAILURE, "invalid group '%s'", primary_group);
		}
		override_gid = true;
	} else if (!uidonly && pw) {
		gid = target_gid;
		override_gid = true;
	}

	if (override_gid) {
		wcred.sc_gid = wcred.sc_rgid = wcred.sc_svgid = gid;
		setcred_flags |= SETCREDF_GID | SETCREDF_RGID | SETCREDF_SVGID;
	}

	if (supp_groups_str) {
		char *groups_copy = strdup(supp_groups_str);
		if (!groups_copy)
			err(EXIT_FAILURE, "malloc failed");

		size_t alloc = 16;
		supp_groups = malloc(sizeof(gid_t) * alloc);
		if (!supp_groups)
			err(EXIT_FAILURE, "malloc failed");

		char *token = strtok(groups_copy, ",");
		while (token) {
			if (supp_count >= alloc) {
				alloc *= 2;
				supp_groups = realloc(supp_groups, sizeof(gid_t) * alloc);
				if (!supp_groups)
					err(EXIT_FAILURE, "realloc failed");
			}
			struct group *gr = getgrnam(token);
			if (gr)
				supp_groups[supp_count++] = gr->gr_gid;
			else {
				const char *errp = NULL;
				gid_t g = strtonum(token, 0, GID_MAX, &errp);
				if (errp != NULL)
					err(EXIT_FAILURE, "invalid supplementary group '%s'", token);
				supp_groups[supp_count++] = g;
			}
			token = strtok(NULL, ",");
		}

		free(groups_copy);
		wcred.sc_supp_groups = supp_groups;
		wcred.sc_supp_groups_nb = supp_count;
		setcred_flags |= SETCREDF_SUPP_GROUPS;

	} else if (!uidonly && pw) {
		/*
		 * If there are too many groups specified for some UID, setting
		 * the groups will fail.  We preserve this condition by
		 * allocating one more group slot than allowed, as
		 * getgrouplist() itself is just some getter function and thus
		 * doesn't (and shouldn't) check the limit, and to allow
		 * setcred() to actually check for overflow.
		 */
		const long ngroups_alloc = sysconf(_SC_NGROUPS_MAX) + 2;
		gid_t *groups = malloc(sizeof(*groups) * ngroups_alloc);
		int ngroups = ngroups_alloc;

		if (groups == NULL)
			err(EXIT_FAILURE, "cannot allocate memory for groups");

		getgrouplist(pw->pw_name, pw->pw_gid, groups, &ngroups);

		wcred.sc_supp_groups = groups + 1;
		wcred.sc_supp_groups_nb = ngroups - 1;
		setcred_flags |= SETCREDF_SUPP_GROUPS;
	}

	if (setcred(setcred_flags, &wcred, sizeof(wcred)) != 0)
		err(EXIT_FAILURE, "calling setcred() failed");

	if (*argv == NULL) {
		const char *sh = getenv("SHELL");
		if (sh == NULL)
			sh = _PATH_BSHELL;
		execlp(sh, sh, "-i", NULL);
	} else {
		execvp(argv[0], argv);
	}
	err(EXIT_FAILURE, "exec failed");
}
