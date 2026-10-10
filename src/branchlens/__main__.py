"""Lets `python -m branchlens` start BranchLens, as the `branchlens` command does."""

import os
import sys

# `python -m` puts the current folder first on sys.path. That folder is often
# the repository being viewed, whose json.py, say, would then be imported in
# place of the standard library's. The entry is dropped before the server loads.
if sys.path and sys.path[0] in ("", os.getcwd()):
    del sys.path[0]

from branchlens import server

server.main()
