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
	fprintf(stderr,
		"Usage: mdo [options] [--] [command [args...]]\n"
		"\n"
		"Options:\n"
		"  -u <user>       Target user (name or UID)\n"
		"  -i              Only change UID, skip groups\n"
		"  -g <group>      Override primary group (name or GID)\n"
		"  -G <g1,g2,...>  Set supplementary groups (name or GID list)\n"
		"  -s <mods>       Modify supplementary groups using:\n"
		"                   +group to add, -group to remove, @ to reset\n"
		"\n"
		"Advanced UID/GID overrides:\n"
		"  -U <ruid>       Set real UID\n"
		"  -R <svuid>      Set saved UID\n"
		"  -E <euid>       Set effective UID\n"
		"  -P <rgid>       Set real GID\n"
		"  -Q <svgid>      Set saved GID\n"
		"\n"
		"  --print-rule	  Print the actual rules of transition in mac.do.rules format\n"
		"  -h              Show this help message\n"
		"\n"
		"Examples:\n"
		"  mdo -u alice id\n"
		"  mdo -u 1001 -g wheel -G staff,operator /bin/sh\n"
		"  mdo -u bob -s @,+wheel,+operator /usr/bin/id\n"
		"  mdo -E 1002 -R 1003 -U 1004 /bin/id\n"
	);
	exit(1);
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

	const char *ruid_str = NULL, *svuid_str = NULL, *euid_str = NULL, *rgid_str = NULL, *svgid_str = NULL;

	bool print_rule = false;
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--print-rule") == 0) {
			print_rule = true;

			for (int j = i; j < argc - 1; j++) {
				argv[j] = argv[j+1];
			}
			argc--;
			break;
		}
	}

	while ((ch = getopt(argc, argv, "u:ig:G:s:U:R:E:P:Q:h")) != -1) {
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
		case 'U':
			ruid_str = optarg;
			break;
		case 'R':
			svuid_str = optarg;
			break;
		case 'E':
			euid_str = optarg;
			break;
		case 'P':
			rgid_str = optarg;
			break;
		case 'Q':
			svgid_str = optarg;
			break;
		case 'h':
			usage();
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

	if (ruid_str) {
		const char *errp = NULL;
		wcred.sc_ruid = strtonum(ruid_str, 0, UID_MAX, &errp);
		if (errp)
			err(EXIT_FAILURE, "-U: invalid UID");
		setcred_flags |= SETCREDF_RUID;
	}
	if (svuid_str) {
		const char *errp = NULL;
		wcred.sc_svuid = strtonum(svuid_str, 0, UID_MAX, &errp);
		if (errp)
			err(EXIT_FAILURE, "-U: invalid UID");
		setcred_flags |= SETCREDF_SVUID;
	}
	if (euid_str) {
		const char *errp = NULL;
		wcred.sc_uid = strtonum(euid_str, 0, UID_MAX, &errp);
		if (errp)
			err(EXIT_FAILURE, "-U: invalid UID");
		setcred_flags |= SETCREDF_UID;
	}
	if (rgid_str) {
		const char *errp = NULL;
		wcred.sc_rgid = strtonum(rgid_str, 0, GID_MAX, &errp);
		if (errp)
			err(EXIT_FAILURE, "-U: invalid GID");
		setcred_flags |= SETCREDF_RGID;
	}
	if (svgid_str) {
		const char *errp = NULL;
		wcred.sc_svuid = strtonum(svgid_str, 0, GID_MAX, &errp);
		if (errp)
			err(EXIT_FAILURE, "-U: invalid GID");
		setcred_flags |= SETCREDF_SVGID;
	}

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

	if (print_rule) {
		uid_t src_uid = getuid();
		gid_t src_gid = getgid();
		int ngroups = getgroups(0, NULL);
		gid_t *groups  = NULL;

		if (ngroups > 0) {
			groups = malloc(sizeof(gid_t) * ngroups);
			if (getgroups(ngroups, groups) < 0)
				err(EXIT_FAILURE, "getgroups() failed");
		}

		fprintf(stdout, "%u:%u", src_uid, src_gid);
		if (ngroups > 0) {
			fprintf(stdout, "+");
			for (int i = 0; i < ngroups; i++) {
				if (i > 0)
					fprintf(stdout, ",");
				fprintf(stdout, "%u", groups[i]);
			}
		}
		fprintf(stdout, " -> ");

		fprintf(stdout, "%u:%u", wcred.sc_uid, wcred.sc_gid);
		if (setcred_flags & SETCREDF_SUPP_GROUPS && wcred.sc_supp_groups_nb > 0) {
			fprintf(stdout, "+");
			for (size_t i = 0; i < wcred.sc_supp_groups_nb; i++) {
				if (i > 0)
					fprintf(stdout, ",");
				fprintf(stdout, "%u", wcred.sc_supp_groups[i]);
			}
		}
		fprintf(stdout, "\n");

		if (groups)
			free(groups);
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
