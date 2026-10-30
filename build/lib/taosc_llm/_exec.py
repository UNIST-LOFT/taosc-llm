"""Minimal isolated-Python exec trampoline for the credential-bearing worker."""

import os
import resource
import sys

# Apply in the child, not globally in the embedding Python application and not
# through a threaded parent's preexec_fn. pass_fds survives this exec unchanged.
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
os.execv(sys.argv[1], sys.argv[1:])
