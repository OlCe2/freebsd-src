/*-
 * Copyright(c) 2024 Baptiste Daroussin <bapt@FreeBSD.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/limits.h>
#include <sys/types.h>
#include <sys/ucred.h>

#include <err.h>
#include <getopt.h>
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
	fprintf(stderr,
		"Usage: mdo [options] [--] [command [args...]]\n"
		"\n"
		"Options:\n"
		"  -u <user>       Target user (name or UID)\n"
		"  -i              Only change UID, skip groups\n"
		"  -g <group>      Override primary group (name or GID)\n"
		"  -k              Keep current user, only change groups\n"
		"  -G <g1,g2,...>  Set supplementary groups (name or GID list)\n"
		"  -s <mods>       Modify supplementary groups using:\n"
		"                   +group to add, -group to remove, @ to reset\n"
		"\n"
		"Advanced UID/GID overrides:\n"
		"  --ruid <uid>       Set real UID\n"
		"  --svuid <uid>      Set saved UID\n"
		"  --euid <uid>       Set effective UID\n"
		"  --rgid <gid>       Set real GID\n"
		"  --svgid <gid>      Set saved GID\n"
		"  --egid <gid>       Set effective GID\n"
		"\n"
		"  --print-rule/-r    Print the actual rules of transition in mac.do.rules format\n"
		"  -h              	  Show this help message\n"
		"\n"
		"Examples:\n"
		"  mdo -u alice id\n"
		"  mdo -u 1001 -g wheel -G staff,operator /bin/sh\n"
		"  mdo -u bob -s @,+wheel,+operator /usr/bin/id\n"
		"  mdo --ruid 1002 -svgid 1003 -egid 1004 /bin/id\n"
	);
	exit(1);
}

static uid_t
parse_user_pwd(const char *s, struct passwd **pwd)
{
	struct passwd *pw = getpwnam(s);
	uid_t uid;
	const char *errp;

	if (pwd != NULL)
		*pwd = pw;

	if (pw != NULL)
		return pw->pw_uid;

	uid = strtonum(s, 0, UID_MAX, &errp);
	if (errp != NULL)
		errx(EXIT_FAILURE, "invalid UID '%s': %s", s, errp);

	return uid;
}

static uid_t
parse_user(const char *s)
{
	return parse_user_pwd(s, NULL);
}

static gid_t
parse_group(const char *s)
{
	struct group *gr = getgrnam(s);
	gid_t gid;
	const char *errp;

	if (gr != NULL)
		return gr->gr_gid;

	gid = strtonum(s, 0, GID_MAX, &errp);
	if (errp != NULL)
		errx(EXIT_FAILURE, "invalid GID '%s': %s", s, errp);

	return gid;
}

static gid_t *
realloc_groups(gid_t *array, size_t new_count)
{
	gid_t *new_array = realloc(array, sizeof(gid_t) * new_count);
	if (new_array == NULL)
		err(EXIT_FAILURE, "realloc of groups failed");
	return new_array;
}

static int
gid_cmp(const void *a, const void *b)
{
	gid_t ga = *(const gid_t *)a;
	gid_t gb = *(const gid_t *)b;
	
	if (ga < gb)
		return -1;
	else if (ga > gb)
		return 1;
	else
		return 0;
}

static size_t
remove_duplicates(gid_t *array, size_t count)
{
	if (count <= 1)
		return count;
	
	qsort(array, count, sizeof(gid_t), gid_cmp);
	
	size_t j = 0;
	for (size_t i = 1; i < count; i++) {
		if (array[i] != array[j]) {
			array[++j] = array[i];
		}
	}
	return j + 1;
}

static size_t
remove_groups_from_array(gid_t *array, size_t count, const gid_t *remove_list, size_t remove_count)
{
	if (remove_count == 0)
		return count;
	
	size_t final_count = 0;
	for (size_t i = 0; i < count; i++) {
		bool should_remove = false;
		for (size_t j = 0; j < remove_count; j++) {
			if (array[i] == remove_list[j]) {
				should_remove = true;
				break;
			}
		}
		if (!should_remove)
			array[final_count++] = array[i];
	}
	return final_count;
}

int
main(int argc, char **argv)
{
	struct passwd *pw = NULL;
	const char *username = "root";
	bool username_provided = false;
	const char *primary_group = NULL;
	const char *supp_groups_str = NULL;
	const char *group_mod_str = NULL;
	struct setcred wcred = SETCRED_INITIALIZER;
	u_int setcred_flags = 0;
	bool uid_only = false;
	bool keep_user = false;
	int ch;

	gid_t gid = -1;
	bool set_all_gids = false;

	bool supp_groups_reset = false;
	gid_t *supp_groups_add = NULL, *groups_supp_del = NULL;
	size_t add_count = 0, rem_count = 0;

	const char *ruid_str = NULL, *svuid_str = NULL, *euid_str = NULL;
	const char *rgid_str = NULL, *svgid_str = NULL, *egid_str = NULL;

	bool print_rule = false;

	const struct option longopts[] = {
		{"ruid", required_argument, NULL, 1000},
		{"svuid", required_argument, NULL, 1001},
		{"euid", required_argument, NULL, 1002},
		{"rgid", required_argument, NULL, 1003},
		{"svgid", required_argument, NULL, 1004},
		{"egid", required_argument, NULL, 1005},
		{"print-rule", no_argument, NULL, 'r'},
		{NULL, 0, NULL, 0}
	};

	while ((ch = getopt_long(argc, argv, "+u:ikg:G:s:rh", longopts, NULL)) != -1) {
		switch (ch) {
		case 'u':
			username = optarg;
			username_provided = true;
			break;
		case 'i':
			uid_only = true;
			break;
		case 'k':
			keep_user = true;
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
		case 1000:
			ruid_str = optarg;
			break;
		case 1001:
			svuid_str = optarg;
			break;
		case 1002:
			euid_str = optarg;
			break;
		case 1003:
			rgid_str = optarg;
			break;
		case 1004:
			svgid_str = optarg;
			break;
		case 1005:
			egid_str = optarg;
			break;
		case 'r':
			print_rule = true;
			break;
		case 'h':
			usage();
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (keep_user && (username_provided || ruid_str != NULL ||
		svuid_str != NULL || euid_str != NULL))
		errx(EXIT_FAILURE, "-k and -u/--ruid/--svuid/--euid cannot be used together");

	if (!keep_user) {
		if (username_provided) {
			uid_t uid = parse_user_pwd(username, &pw);

			if (pw == NULL && primary_group == NULL)
				errx(EXIT_FAILURE, "must specify -g when using a numeric UID");

			wcred.sc_uid = wcred.sc_ruid = wcred.sc_svuid = uid;
			setcred_flags |= SETCREDF_UID | SETCREDF_RUID | SETCREDF_SVUID;
		}

		if (ruid_str != NULL) {
			wcred.sc_ruid = parse_user(ruid_str);
			setcred_flags |= SETCREDF_RUID;
		}
		if (svuid_str != NULL) {
			wcred.sc_svuid = parse_user(svuid_str);
			setcred_flags |= SETCREDF_SVUID;
		}
		if (euid_str != NULL) {
			wcred.sc_uid = parse_user(euid_str);
			setcred_flags |= SETCREDF_UID;
		}
	} else {
		pw = getpwuid(geteuid());
		if (pw == NULL)
			err(EXIT_FAILURE, "cannot determine current user");
	}

	if (primary_group != NULL) {
		gid = parse_group(primary_group);
		set_all_gids = true;
	} else if (pw != NULL && !uid_only) {
		gid = pw->pw_gid;
		set_all_gids = true;
	} else if (ruid_str != NULL || svuid_str != NULL || euid_str != NULL) {
		gid = getegid();
		set_all_gids = true;
	} else {
		errx(EXIT_FAILURE, 
			"must specify '-g' or some user that has an entry in the password database");
	}

	if (set_all_gids) {
		wcred.sc_gid = wcred.sc_rgid = wcred.sc_svgid = gid;
		setcred_flags |= SETCREDF_GID | SETCREDF_RGID | SETCREDF_SVGID;
	}

	if (rgid_str != NULL) {
		wcred.sc_rgid = parse_group(rgid_str);
		setcred_flags |= SETCREDF_RGID;
	}
	if (svgid_str != NULL) {
		wcred.sc_svgid = parse_group(svgid_str);
		setcred_flags |= SETCREDF_SVGID;
	}
	if (egid_str != NULL) {
		wcred.sc_gid = parse_group(egid_str);
		setcred_flags |= SETCREDF_GID;
	}
	
	if (supp_groups_str != NULL) {
		char *s = strdup(supp_groups_str);
		char *p = s;
		char *tok;

		if (s == NULL)
			err(EXIT_FAILURE, "strdup failed for supplementary groups string");

		while ((tok = strsep(&p, ",")) != NULL) {
			gid_t g;
			if (*tok == '\0')
				continue;

			g = parse_group(tok);
			supp_groups_add = realloc_groups(supp_groups_add, add_count + 1);
			supp_groups_add[add_count++] = g;
		}
		free(s);
		supp_groups_reset = true;
	}

	if (group_mod_str != NULL) {
		int i = 0;
		char *s = strdup(group_mod_str);
		char *p = s;
		char *tok;

		if (s == NULL)
			err(EXIT_FAILURE, "strdup failed for group modification string");

		while ((tok = strsep(&p, ",")) != NULL) {
			if (*tok == '\0')
				continue;

			if (tok[0] == '@')  {
				if (i > 0)
					errx(EXIT_FAILURE, "'@' must be the first token in -s option");
				supp_groups_reset = true;
			} else if (tok[0] == '+' || tok[0] == '-') {
				bool is_add = tok[0] == '+';
				const char *gstr = tok + 1;
				gid = parse_group(gstr);
				if (is_add) {
					supp_groups_add = realloc_groups(supp_groups_add, add_count + 1);
					supp_groups_add[add_count++] = gid;
				} else {
					groups_supp_del = realloc_groups(groups_supp_del, rem_count + 1);
					groups_supp_del[rem_count++] = gid;
				}
			} else {
				errx(EXIT_FAILURE, "invalid -s entry '%s'", tok);
			}
			i++;
		}
		free(s);
	}

	if (supp_groups_reset) {
		wcred.sc_supp_groups = NULL;
		wcred.sc_supp_groups_nb = 0;
		setcred_flags |= SETCREDF_SUPP_GROUPS;
	} else {
		if (pw != NULL && !uid_only) {
			gid_t *groups = NULL;
			int base_count = 0;
			const long ngroups_alloc = sysconf(_SC_NGROUPS_MAX) + 2;

			/*
			 * If there are too many groups specified for some UID, setting
			 * the groups will fail.  We preserve this condition by
			 * allocating one more group slot than allowed, as
			 * getgrouplist() itself is just some getter function and thus
			 * doesn't (and shouldn't) check the limit, and to allow
			 * setcred() to actually check for overflow.
			 */
			groups = malloc(sizeof(*groups) * ngroups_alloc);
			if (groups == NULL)
				err(EXIT_FAILURE, "cannot allocate memory for user groups from database");
			base_count = ngroups_alloc;
			getgrouplist(pw->pw_name, pw->pw_gid, groups, &base_count);

			for (int i = 0; i < base_count; ++i) {
				supp_groups_add = realloc_groups(supp_groups_add, add_count + 1);
				supp_groups_add[add_count++] = groups[i];
			}
			free(groups);
		} else {
			int ngroups = getgroups(0, NULL);
			if (ngroups > 0) {
				gid_t *groups = malloc(sizeof(gid_t) * ngroups);
				if (groups == NULL)
					err(EXIT_FAILURE, "cannot allocate memory for current user groups");
				if (getgroups(ngroups, groups) < 0)
					err(EXIT_FAILURE, "getgroups() failed");

				for (int i = 0; i < ngroups; ++i) {
					supp_groups_add = realloc_groups(supp_groups_add, add_count + 1);
					supp_groups_add[add_count++] = groups[i];
				}
				free(groups);
			}
		}
	}

	if (supp_groups_add != NULL || groups_supp_del != NULL) {
		gid_t *final;
		size_t final_count = 0;

		final = malloc(sizeof(gid_t) * (add_count + rem_count + 4));

		if (final == NULL)
			err(EXIT_FAILURE, "cannot allocate memory for final supplementary groups");

		for (size_t i = 0; i < add_count; ++i) {
			final[final_count++] = supp_groups_add[i];
		}

		final_count = remove_duplicates(final, final_count);

		final_count = remove_groups_from_array(final, final_count, groups_supp_del, rem_count);

		wcred.sc_supp_groups = final;
		wcred.sc_supp_groups_nb = final_count;
		setcred_flags |= SETCREDF_SUPP_GROUPS;
	}

	if (print_rule) {
		fprintf(stdout, "uid=%u,gid=%u,", wcred.sc_uid, wcred.sc_gid);
		if (setcred_flags & SETCREDF_SUPP_GROUPS && wcred.sc_supp_groups_nb > 0) {
			fprintf(stdout, "+gid=");
			for (size_t i = 0; i < wcred.sc_supp_groups_nb; i++) {
				if (i > 0)
					fprintf(stdout, ",");
				fprintf(stdout, "%u", wcred.sc_supp_groups[i]);
			}
		}
		fprintf(stdout, "\n");

		exit(0);
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
