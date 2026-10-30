#!/usr/bin/env python3
"""One-command demo: python3 demo.py

Shows the full 0-RTT path, a replay rejected by the filter, a replay that gets
past a deliberately bypassed filter but is deduplicated by the commit store,
an expired ticket, and a legacy client without the guard extension.
"""

from tls13pq.demo import main

if __name__ == "__main__":
    raise SystemExit(main())
