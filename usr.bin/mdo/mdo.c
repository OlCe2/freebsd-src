/*-
 * Copyright(c) 2024 Baptiste Daroussin <bapt@FreeBSD.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/limits.h>
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
	fprintf(stderr, "usage: mdo [-u username] [-i] [-g primary] [-G supplementary] [-s add/remove supplementary] [--] [command [args]]\n");
	exit(EXIT_FAILURE);
}

int
main(int argc, char **argv)
{
	struct passwd *pw = NULL;
	const char *username = "root";
	const char *primary_group = NULL;
	const char *supp_groups_str = NULL;
	const char *group_mod_str = NULL;
	struct setcred wcred = SETCRED_INITIALIZER;
	u_int setcred_flags = 0;
	bool uidonly = false;
	int ch;

	gid_t gid = -1;
	bool override_gid = false;

	bool supp_reset = false;
	gid_t *supp_add = NULL, *supp_rem = NULL;
	size_t add_count = 0, rem_count = 0;

	while ((ch = getopt(argc, argv, "u:ig:G:s:")) != -1) {
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
		case 's':
			group_mod_str = optarg;
			break;
		default:
			usage();
		}
	}

	if (uidonly && (primary_group || supp_groups_str || group_mod_str))
		errx(EXIT_FAILURE, "-i cannot be used with -g, -G, or -s");

	argc -= optind;
	argv += optind;

	if (username) {
		if ((pw = getpwnam(username)) == NULL) {
			if (strspn(username, "0123456789") == strlen(username)) {
				const char *errp = NULL;
				uid_t uid = strtonum(username, 0, UID_MAX, &errp);
				if (errp != NULL)
					err(EXIT_FAILURE, "invalid user ID '%s'", username);
				pw = getpwuid(uid);
			}
			if (pw == NULL)
				err(EXIT_FAILURE, "invalid username '%s'", username);
		}
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
		gid = pw->pw_gid;
		override_gid = true;
	}

	if (override_gid) {
		wcred.sc_gid = wcred.sc_rgid = wcred.sc_svgid = gid;
		setcred_flags |= SETCREDF_GID | SETCREDF_RGID | SETCREDF_SVGID;
	}

	if (supp_groups_str) {
		char *copy = strdup(supp_groups_str);
		if (!copy)
			err(EXIT_FAILURE, "strdup failed");
		char *tok = strtok(copy, ",");
		while (tok) {
			struct group *gr = getgrnam(tok);
			gid_t g;
			if (gr)
				g = gr->gr_gid;
			else {
				const char *errp = NULL;
				g = strtonum(tok, 0, GID_MAX, &errp);
				if (errp != NULL)
					err(EXIT_FAILURE, "invalid group '%s", tok);
			}
			supp_add = realloc(supp_add, sizeof(gid_t) * (add_count + 1));
			if (!supp_add)
				err(EXIT_FAILURE, "realloc failed");
			supp_add[add_count++] = g;
			tok = strtok(NULL, ",");
		}
		free(copy);
		supp_reset = true;
	}

	if (group_mod_str) {
		char *s = strdup(group_mod_str);
		if (!s)
			err(EXIT_FAILURE, "strdup failed");
		char *tok = strtok(s, ",");
		while (tok) {
			if (strcmp(tok, "@") == 0) {
				supp_reset = true;
			} else if (tok[0] == '+' || tok[0] == '-') {
				bool is_add = tok[0] == '+';
				const char *gstr = tok + 1;
				struct group *gr = getgrnam(gstr);
				if (gr)
					gid = gr->gr_gid;
				else {
					const char *errp = NULL;
					gid = strtonum(gstr, 0, GID_MAX, &errp);
					if (errp != NULL)
						err(EXIT_FAILURE, "invalid group '%s'", gstr);
				}
				if (is_add) {
					supp_add = realloc(supp_add, sizeof(gid_t) * (add_count + 1));
					if (!supp_add) err(EXIT_FAILURE, "realloc failed");
					supp_add[add_count++] = gid;
				} else {
					supp_rem = realloc(supp_rem, sizeof(gid_t) * (rem_count + 1));
					if (!supp_rem) err(EXIT_FAILURE, "realloc failed");
					supp_rem[rem_count++] = gid;
				}
			} else {
				errx(EXIT_FAILURE, "invalid -s entry '%s'", tok);
			}
			tok = strtok(NULL, ",");
		}
		free(s);
	}

	if (supp_reset) {
		gid_t *final = NULL;
		size_t final_count = 0;

		if (add_count > 0) {
			final = malloc(sizeof(gid_t) * add_count);
			if (!final)
				err(EXIT_FAILURE, "malloc failed");

			for (size_t i = 0; i < add_count; ++i) {
				final[final_count++] = supp_add[i];
			}
		}

		wcred.sc_supp_groups = final;
		wcred.sc_supp_groups_nb = final_count;
		setcred_flags |= SETCREDF_SUPP_GROUPS;
	} else if (!supp_reset && (group_mod_str || !uidonly)) {
		gid_t *base = NULL;
		int base_count = 0;
		size_t alloc;
		gid_t *final;
		size_t final_count = 0;

		/*
		 * If there are too many groups specified for some UID, setting
		 * the groups will fail.  We preserve this condition by
		 * allocating one more group slot than allowed, as
		 * getgrouplist() itself is just some getter function and thus
		 * doesn't (and shouldn't) check the limit, and to allow
		 * setcred() to actually check for overflow.
		 */
		if (!supp_reset && pw) {
			const long max = sysconf(_SC_NGROUPS_MAX) + 2;
			base = malloc(sizeof(*base) * max);
			if (!base)
				err(EXIT_FAILURE, "malloc failed");
			base_count = max;
			getgrouplist(pw->pw_name, pw->pw_gid, base, &base_count);
		}

		alloc = base_count + add_count + rem_count + 4;
		final = malloc(sizeof(gid_t) * alloc);

		if (!final)
			err(EXIT_FAILURE, "malloc failed");

		for (int i = 0; i < base_count; ++i) {
			bool skip = false;
			for (size_t j = 0; j < rem_count; ++j) {
				if (base[i] == supp_rem[j]) {
					skip = true;
					break;
				}
			}

			for (size_t j = 0; j < final_count && !skip; ++j) {
				if (final[j] == base[i]) {
					skip = true;
					break;
				}
			}
			if (!skip)
				final[final_count++] = base[i];
		}

		for (size_t i = 0; i < add_count; ++i) {
			bool exists = false;
			for (size_t j = 0; j < final_count; ++j) {
				if (final[j] == supp_add[i]) {
					exists = true;
					break;
				}
			}
			if (!exists)
				final[final_count++] = supp_add[i];
		}

		wcred.sc_supp_groups = final;
		wcred.sc_supp_groups_nb = final_count;
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
