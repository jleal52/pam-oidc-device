/*
 * Thin C helpers for the cgo PAM module.
 *
 * Everything that needs a C struct layout (the conversation) or a C macro
 * (PAM_RHOST, PAM_CONV, PAM_TEXT_INFO) lives here so that the Go side only
 * ever calls plain functions. All helpers are static inline: there is no
 * separate translation unit and no symbol other than pam_sm_* leaves the
 * shared object.
 */
#ifndef PAM_OIDC_DEVICE_SHIM_H
#define PAM_OIDC_DEVICE_SHIM_H

#include <stdlib.h>
#include <string.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>

/*
 * The pam_sm_* prototypes in <security/pam_modules.h> take "const char **argv".
 * cgo cannot express pointer-to-const, so the Go side declares argv as
 * *C.pam_argv_t; cgo then emits "pam_argv_t *argv", which is the same type.
 */
typedef const char *pam_argv_t;

/*
 * The Go package internal/pammap mirrors these values so that the mapping
 * can be tested without cgo. Fail the build rather than silently diverge.
 */
_Static_assert(PAM_SUCCESS == 0, "PAM_SUCCESS changed; update internal/pammap");
_Static_assert(PAM_AUTH_ERR == 7, "PAM_AUTH_ERR changed; update internal/pammap");
_Static_assert(PAM_AUTHINFO_UNAVAIL == 9, "PAM_AUTHINFO_UNAVAIL changed; update internal/pammap");
_Static_assert(PAM_USER_UNKNOWN == 10, "PAM_USER_UNKNOWN changed; update internal/pammap");
_Static_assert(PAM_IGNORE == 25, "PAM_IGNORE changed; update internal/pammap");

/*
 * shim_get_user resolves the user being authenticated. PAM owns the returned
 * string; it must not be freed and is only valid while the handle lives.
 * Passing NULL as the prompt makes libpam use the default "login:" prompt if
 * the application did not set PAM_USER (sshd always does).
 */
static inline int shim_get_user(pam_handle_t *h, const char **user)
{
	return pam_get_user(h, user, NULL);
}

/*
 * shim_get_rhost returns PAM_RHOST or "" when it is unset. PAM owns the
 * string; it must not be freed.
 */
static inline const char *shim_get_rhost(pam_handle_t *h)
{
	const void *item = NULL;

	if (pam_get_item(h, PAM_RHOST, &item) != PAM_SUCCESS || item == NULL)
		return "";
	return (const char *)item;
}

/*
 * shim_info shows one PAM_TEXT_INFO message through the application's
 * conversation function and returns the conversation's return code. The
 * response array is freed here (the module owns it after the call). A
 * missing conversation yields PAM_CONV_ERR instead of a NULL dereference.
 */
static inline int shim_info(pam_handle_t *h, const char *msg)
{
	const void *item = NULL;
	const struct pam_conv *conv;
	struct pam_message pmsg;
	const struct pam_message *pmsgp = &pmsg;
	struct pam_response *resp = NULL;
	int rc;

	rc = pam_get_item(h, PAM_CONV, &item);
	if (rc != PAM_SUCCESS)
		return rc;
	conv = (const struct pam_conv *)item;
	if (conv == NULL || conv->conv == NULL)
		return PAM_CONV_ERR;

	memset(&pmsg, 0, sizeof(pmsg));
	pmsg.msg_style = PAM_TEXT_INFO;
	pmsg.msg = msg;

	rc = conv->conv(1, &pmsgp, &resp, conv->appdata_ptr);
	if (resp != NULL) {
		if (resp->resp != NULL)
			free(resp->resp);
		free(resp);
	}
	return rc;
}

/*
 * shim_putenv adds "NAME=value" to the PAM environment. libpam copies the
 * string, so the caller keeps ownership of kv.
 */
static inline int shim_putenv(pam_handle_t *h, const char *kv)
{
	return pam_putenv(h, kv);
}

#endif /* PAM_OIDC_DEVICE_SHIM_H */
