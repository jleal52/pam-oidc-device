/*
 * pam_oidc_device — thin PAM module that delegates the OpenID Connect
 * Device Authorization Grant to a helper process.
 *
 * Why a helper process: OpenSSH runs pam_authenticate() in a child it
 * creates with fork() (its "pthread emulation"), and a Go runtime that was
 * initialised when the shared object was loaded does not survive a fork
 * without exec. Keeping this module in plain C and doing all the work in a
 * freshly exec'ed Go binary sidesteps the problem entirely: sshd never hosts
 * a Go runtime, and the helper is an ordinary process.
 *
 * Protocol (helper stdout → module), one line each, '\n'-terminated:
 *   I <text>            PAM_TEXT_INFO message for the user
 *   P <text>            PAM_PROMPT_ECHO_OFF; the module writes one line to the
 *                       helper's stdin when the user has answered (the answer
 *                       is discarded, it is only an acknowledgement)
 *   E <NAME>=<value>    environment variable to export into the session
 *   R <code> <reason>   final result; code is one of
 *                       success | ignore | auth_err | authinfo_unavail | user_unknown
 * Anything else, EOF before "R", a malformed line, a helper crash or the
 * wall-clock timeout maps to PAM_AUTHINFO_UNAVAIL (fail closed).
 *
 * Module arguments:
 *   config=<path>   configuration file (default /etc/security/pam_oidc_device.yaml)
 *   helper=<path>   helper binary (default /usr/libexec/pam-oidc-device/pam-oidc-device-helper)
 *   timeout=<sec>   wall-clock bound for the whole exchange (default 420)
 *   debug           forwarded to the helper (verbose syslog)
 *
 * Copyright 2026 Jorge Leal. Licensed under the Apache License, Version 2.0.
 */

/* POSIX only: _GNU_SOURCE on glibc >= 2.38 redirects strtol to
 * __isoc23_strtol, which makes the object refuse to load on older systems. */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <security/pam_appl.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>

#define DEFAULT_CONFIG  "/etc/security/pam_oidc_device.yaml"
#define DEFAULT_HELPER  "/usr/libexec/pam-oidc-device/pam-oidc-device-helper"
#define DEFAULT_TIMEOUT 420
#define MAX_LINE        8192
#define MAX_INFO        4096
/* How long to let the helper finish exiting after it has sent its result
 * line, and how often to look while waiting. See reap_helper. */
#define EXIT_GRACE_MS   2000
#define EXIT_POLL_NS    (2L * 1000 * 1000)

struct opts {
    const char *config;
    const char *helper;
    long timeout;
    int debug;
};

static void parse_opts(pam_handle_t *pamh, int argc, const char **argv, struct opts *o)
{
    o->config = DEFAULT_CONFIG;
    o->helper = DEFAULT_HELPER;
    o->timeout = DEFAULT_TIMEOUT;
    o->debug = 0;
    for (int i = 0; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "debug") == 0) {
            o->debug = 1;
        } else if (strncmp(a, "config=", 7) == 0 && a[7] != '\0') {
            o->config = a + 7;
        } else if (strncmp(a, "helper=", 7) == 0 && a[7] != '\0') {
            o->helper = a + 7;
        } else if (strncmp(a, "timeout=", 8) == 0) {
            char *end = NULL;
            long v = strtol(a + 8, &end, 10);
            if (end && *end == '\0' && v > 0 && v <= 86400)
                o->timeout = v;
            else
                pam_syslog(pamh, LOG_NOTICE, "ignoring invalid timeout argument %s", a);
        } else {
            pam_syslog(pamh, LOG_NOTICE, "ignoring unknown module argument %s", a);
        }
    }
}

/* Runs one conversation message of the given style; the response, if any,
 * is discarded. Errors are logged, never fatal. */
static void converse(pam_handle_t *pamh, int style, const char *text)
{
    const struct pam_conv *conv = NULL;
    if (pam_get_item(pamh, PAM_CONV, (const void **)&conv) != PAM_SUCCESS || conv == NULL || conv->conv == NULL)
        return;
    struct pam_message msg = { .msg_style = style, .msg = text };
    const struct pam_message *pmsg = &msg;
    struct pam_response *resp = NULL;
    int rc = conv->conv(1, &pmsg, &resp, conv->appdata_ptr);
    if (resp != NULL) {
        free(resp->resp);
        free(resp);
    }
    if (rc != PAM_SUCCESS)
        pam_syslog(pamh, LOG_WARNING, "conversation failed: %s", pam_strerror(pamh, rc));
}

/* Drops control characters except '\n' and '\t'; bytes >= 0x80 pass
 * unchanged (UTF-8). Returns a newly allocated string. */
static char *sanitize_text(const char *s, size_t max)
{
    size_t n = strlen(s);
    if (n > max)
        n = max;
    char *out = malloc(n + 1);
    if (out == NULL)
        return NULL;
    size_t j = 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c >= 0x80 || c == '\n' || c == '\t' || (c >= 0x20 && c != 0x7f))
            out[j++] = (char)c;
    }
    out[j] = '\0';
    return out;
}

static int valid_env_name(const char *name, size_t len)
{
    if (len == 0 || len > 128)
        return 0;
    if (!(isalpha((unsigned char)name[0]) || name[0] == '_'))
        return 0;
    for (size_t i = 1; i < len; i++)
        if (!(isalnum((unsigned char)name[i]) || name[i] == '_'))
            return 0;
    return 1;
}

static int valid_env_value(const char *v)
{
    for (const unsigned char *p = (const unsigned char *)v; *p; p++)
        if (*p < 0x20 || *p == 0x7f)
            return 0;
    return 1;
}

static int map_result(const char *code)
{
    if (strcmp(code, "success") == 0) return PAM_SUCCESS;
    if (strcmp(code, "ignore") == 0) return PAM_IGNORE;
    if (strcmp(code, "auth_err") == 0) return PAM_AUTH_ERR;
    if (strcmp(code, "user_unknown") == 0) return PAM_USER_UNKNOWN;
    return PAM_AUTHINFO_UNAVAIL;
}

static long now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

/* Reaps the helper, giving it up to grace_ms to exit on its own. Returns 1
 * when there is nothing left to wait for (it was reaped, or waitpid says it
 * is not ours), 0 when it is still running.
 *
 * The grace period is not politeness. The helper writes its result line and
 * only then flushes, unwinds and exits, so a WNOHANG the instant that line
 * arrives nearly always finds it alive; killing it there and reading the
 * signal out of the status would discard a successful authentication as an
 * abnormal exit. With grace_ms == 0 this is exactly one WNOHANG call. */
static int reap_helper(pid_t pid, int *status, long grace_ms)
{
    long deadline = now_ms() + grace_ms;
    for (;;) {
        if (waitpid(pid, status, WNOHANG) != 0)
            return 1;
        if (now_ms() >= deadline)
            return 0;
        struct timespec ts = { .tv_sec = 0, .tv_nsec = EXIT_POLL_NS };
        nanosleep(&ts, NULL);
    }
}

/* Handles one protocol line. Returns 1 when the final result was received
 * (stored in *rc), 0 to keep reading, -1 on a protocol violation. */
static int handle_line(pam_handle_t *pamh, char *line, int *rc, int ackfd)
{
    if (line[0] == '\0' || line[1] != ' ')
        return -1;
    char *arg = line + 2;
    switch (line[0]) {
    case 'I':
    case 'P': {
        char *txt = sanitize_text(arg, MAX_INFO);
        if (txt == NULL)
            return -1;
        converse(pamh, line[0] == 'I' ? PAM_TEXT_INFO : PAM_PROMPT_ECHO_OFF, txt);
        free(txt);
        if (line[0] == 'P') {
            /* Acknowledge so the helper starts polling; a failed write only
             * means the helper sees EOF and polls anyway. */
            ssize_t w;
            do {
                w = write(ackfd, "\n", 1);
            } while (w < 0 && errno == EINTR);
        }
        return 0;
    }
    case 'E': {
        char *eq = strchr(arg, '=');
        if (eq == NULL || !valid_env_name(arg, (size_t)(eq - arg)) || !valid_env_value(eq + 1)) {
            pam_syslog(pamh, LOG_ERR, "helper sent an invalid environment entry");
            return -1;
        }
        int prc = pam_putenv(pamh, arg);
        if (prc != PAM_SUCCESS) {
            pam_syslog(pamh, LOG_ERR, "pam_putenv failed: %s", pam_strerror(pamh, prc));
            return -1;
        }
        return 0;
    }
    case 'R': {
        char *sp = strchr(arg, ' ');
        if (sp != NULL)
            *sp = '\0';
        *rc = map_result(arg);
        return 1;
    }
    default:
        return -1;
    }
}

/* pipe() with both ends close-on-exec (pipe2 needs _GNU_SOURCE). */
static int make_pipe(int fd[2])
{
    if (pipe(fd) != 0)
        return -1;
    for (int i = 0; i < 2; i++) {
        int fl = fcntl(fd[i], F_GETFD);
        if (fl < 0 || fcntl(fd[i], F_SETFD, fl | FD_CLOEXEC) < 0) {
            close(fd[0]);
            close(fd[1]);
            return -1;
        }
    }
    return 0;
}

static void close_inherited_fds(int keep)
{
    long maxfd = sysconf(_SC_OPEN_MAX);
    if (maxfd < 0 || maxfd > 65536)
        maxfd = 65536;
    for (int fd = 3; fd < maxfd; fd++)
        if (fd != keep)
            close(fd);
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    (void)flags;
    struct opts o;
    parse_opts(pamh, argc, argv, &o);

    const char *user = NULL;
    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || user == NULL || *user == '\0')
        return PAM_USER_UNKNOWN;
    const char *rhost = NULL;
    if (pam_get_item(pamh, PAM_RHOST, (const void **)&rhost) != PAM_SUCCESS || rhost == NULL)
        rhost = "";

    if (access(o.helper, X_OK) != 0) {
        pam_syslog(pamh, LOG_ERR, "helper %s is not executable: %m", o.helper);
        return PAM_AUTHINFO_UNAVAIL;
    }

    int pipefd[2];  /* helper stdout → module */
    int ackfd[2];   /* module → helper stdin (prompt acknowledgements) */
    if (make_pipe(pipefd) != 0 || make_pipe(ackfd) != 0) {
        pam_syslog(pamh, LOG_ERR, "pipe: %m");
        return PAM_AUTHINFO_UNAVAIL;
    }

    pid_t pid = fork();
    if (pid < 0) {
        pam_syslog(pamh, LOG_ERR, "fork: %m");
        close(pipefd[0]); close(pipefd[1]);
        close(ackfd[0]); close(ackfd[1]);
        return PAM_AUTHINFO_UNAVAIL;
    }
    if (pid == 0) {
        /* Child: stdout → pipe, stdin ← ack pipe, stderr kept for the
         * helper's syslog fallback, everything else closed. */
        if (dup2(pipefd[1], STDOUT_FILENO) < 0 || dup2(ackfd[0], STDIN_FILENO) < 0)
            _exit(127);
        close_inherited_fds(-1);
        const char *args[10];
        int n = 0;
        args[n++] = o.helper;
        args[n++] = "--config";
        args[n++] = o.config;
        args[n++] = "--user";
        args[n++] = user;
        args[n++] = "--rhost";
        args[n++] = rhost;
        if (o.debug)
            args[n++] = "--debug";
        args[n] = NULL;
        char *const env[] = { (char *)"PATH=/usr/sbin:/usr/bin:/sbin:/bin", NULL };
        execve(o.helper, (char *const *)args, env);
        _exit(127);
    }

    close(pipefd[1]);
    close(ackfd[0]);
    /* The helper may exit while an acknowledgement is being written. */
    signal(SIGPIPE, SIG_IGN);
    int rc = PAM_AUTHINFO_UNAVAIL;
    int done = 0;
    char buf[MAX_LINE];
    size_t len = 0;
    long deadline = now_ms() + o.timeout * 1000L;

    while (!done) {
        long left = deadline - now_ms();
        if (left <= 0) {
            pam_syslog(pamh, LOG_ERR, "helper did not finish within %ld s", o.timeout);
            break;
        }
        struct pollfd pfd = { .fd = pipefd[0], .events = POLLIN };
        int pr = poll(&pfd, 1, left > 2147483647L ? 2147483647 : (int)left);
        if (pr < 0) {
            if (errno == EINTR)
                continue;
            pam_syslog(pamh, LOG_ERR, "poll: %m");
            break;
        }
        if (pr == 0)
            continue;
        ssize_t r = read(pipefd[0], buf + len, sizeof(buf) - 1 - len);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            pam_syslog(pamh, LOG_ERR, "read: %m");
            break;
        }
        if (r == 0) {
            pam_syslog(pamh, LOG_ERR, "helper exited without a result");
            break;
        }
        len += (size_t)r;
        buf[len] = '\0';
        char *start = buf;
        char *nl;
        while ((nl = memchr(start, '\n', len - (size_t)(start - buf))) != NULL) {
            *nl = '\0';
            int h = handle_line(pamh, start, &rc, ackfd[1]);
            if (h < 0) {
                pam_syslog(pamh, LOG_ERR, "protocol violation from helper");
                rc = PAM_AUTHINFO_UNAVAIL;
                done = 1;
                break;
            }
            if (h > 0) {
                done = 1;
                break;
            }
            start = nl + 1;
        }
        if (!done) {
            size_t rest = len - (size_t)(start - buf);
            if (rest >= sizeof(buf) - 1) {
                pam_syslog(pamh, LOG_ERR, "helper line too long");
                rc = PAM_AUTHINFO_UNAVAIL;
                break;
            }
            memmove(buf, start, rest);
            len = rest;
        }
    }

    close(pipefd[0]);
    close(ackfd[1]);
    int status = 0;
    /* A helper that has delivered its result is on its way out and gets a
     * moment to get there; one that never did is stuck and is killed at
     * once, the wall-clock deadline having already passed. */
    if (!reap_helper(pid, &status, done ? EXIT_GRACE_MS : 0)) {
        kill(pid, SIGKILL);
        while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
            ;
    }
    if (done && rc == PAM_SUCCESS && (!WIFEXITED(status) || WEXITSTATUS(status) != 0)) {
        /* A success line followed by an abnormal exit is not trusted. */
        pam_syslog(pamh, LOG_ERR, "helper reported success but exited abnormally");
        rc = PAM_AUTHINFO_UNAVAIL;
    }
    return rc;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return PAM_SUCCESS;
}

/* The module contributes nothing to the account stack: PAM_IGNORE, so that a
 * stray "account required pam_oidc_device.so" line cannot let everyone in. */
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return PAM_IGNORE;
}
