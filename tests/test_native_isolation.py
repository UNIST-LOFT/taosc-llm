"""Real syscall boundaries on a harmless program, without model credentials."""

import json
import shutil
import signal

import pytest
from taosc_llm.native import run_native

PROBE = r'''
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc != 2) return 90;
    int secret = open(argv[1], O_RDONLY);
    int proc = open("/proc/self/environ", O_RDONLY);
    int network = socket(AF_INET, SOCK_STREAM, 0);
    int truncated = truncate(argv[1], 0);
    FILE *allowed = fopen("allowed.txt", "w");
    if (allowed) { fputs("permitted scratch write", allowed); fclose(allowed); }
    printf("{\"private_denied\":%s,\"proc_denied\":%s,\"network_denied\":%s,"
           "\"truncate_denied\":%s,\"scratch_written\":%s,\"credential_absent\":%s}\n",
           secret == -1 ? "true":"false", proc == -1 ? "true":"false",
           network == -1 ? "true":"false", truncated == -1 ? "true":"false",
           allowed ? "true":"false", getenv("OPENAI_API_KEY") ? "false":"true");
    return 0;
}
'''


def test_native_private_files_network_and_credentials_are_inaccessible(tmp_path, monkeypatch):
    gcc = shutil.which("gcc")
    if gcc is None:
        pytest.skip("native isolation probe requires gcc")
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    source = scratch / "probe.c"
    source.write_text(PROBE)
    binary = scratch / "probe"
    secret = tmp_path / "private.txt"
    secret.write_text("private fixture value")
    monkeypatch.setenv("OPENAI_API_KEY", "never-pass-to-native-child")
    run_native([gcc, str(source), "-o", str(binary)], scratch)
    result = run_native([str(binary), str(secret)], scratch, timeout=5)
    assert json.loads(result.stdout) == {
        "private_denied": True, "proc_denied": True, "network_denied": True,
        "truncate_denied": True, "scratch_written": True, "credential_absent": True,
    }
    assert secret.read_text() == "private fixture value"
    assert (scratch / "allowed.txt").read_text() == "permitted scratch write"


def test_self_abort_preserves_signal_without_signaling_peers(tmp_path):
    gcc = shutil.which("gcc")
    if gcc is None:
        pytest.skip("native signal probe requires gcc")
    source = tmp_path / "signals.c"
    source.write_text(r'''
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
static int creation_denied(long number) {
    long result = syscall(number, SIGCHLD, 0, 0, 0, 0);
    if (result == 0) _exit(0);
    if (result > 0) { waitpid(result, NULL, 0); return 0; }
    return errno == EPERM;
}
int main(int argc, char **argv) {
    if (argc == 2 && argv[1][0] == 'a') abort();
    if (argc == 2) {
        int denied = syscall(SYS_tgkill, getpid(), syscall(SYS_gettid), 0) == -1 && errno == EPERM;
        printf("{\"self_denied\":%d}\n", denied);
        return 0;
    }
    pid_t self = getpid(), peer = getppid();
    int self_allowed = syscall(SYS_tgkill, self, syscall(SYS_gettid), 0) == 0;
    int peer_denied = syscall(SYS_tgkill, peer, peer, 0) == -1 && errno == EPERM;
    int foreign_tid_denied = syscall(SYS_tgkill, self, peer, 0) == -1 && errno == ESRCH;
    int kill_denied = kill(peer, 0) == -1 && errno == EPERM;
    int tkill_denied = syscall(SYS_tkill, peer, 0) == -1 && errno == EPERM;
    printf("{\"self_allowed\":%d,\"peer_denied\":%d,\"foreign_tid_denied\":%d,"
           "\"kill_denied\":%d,\"tkill_denied\":%d,\"fork_denied\":%d,"
           "\"vfork_denied\":%d,\"clone_denied\":%d,\"clone3_denied\":%d}\n",
           self_allowed, peer_denied, foreign_tid_denied, kill_denied, tkill_denied,
           creation_denied(SYS_fork), creation_denied(SYS_vfork),
           creation_denied(SYS_clone), creation_denied(SYS_clone3));
    return 0;
}
''')
    binary = tmp_path / "signals"
    run_native([gcc, str(source), "-o", str(binary)], tmp_path)
    default = run_native([str(binary), "policy"], tmp_path, timeout=5)
    assert json.loads(default.stdout) == {"self_denied": 1}
    result = run_native([str(binary)], tmp_path, timeout=5, self_signals=True)
    assert json.loads(result.stdout) == {
        "self_allowed": 1, "peer_denied": 1, "foreign_tid_denied": 1,
        "kill_denied": 1, "tkill_denied": 1, "fork_denied": 1,
        "vfork_denied": 1, "clone_denied": 1, "clone3_denied": 1,
    }
    aborted = run_native([str(binary), "abort"], tmp_path, timeout=5, check=False,
                         self_signals=True)
    assert aborted.returncode == -signal.SIGABRT
