"""Real syscall boundaries on a harmless program, without model credentials."""

import json
import shutil

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
