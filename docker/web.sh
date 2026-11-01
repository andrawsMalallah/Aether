#!/bin/sh
set -eu
# Render sends TERM. Apache drains on WINCH; retain PID 1 to reap the child.
apache2 -DFOREGROUND >/dev/null 2>&1 &
apache_pid=$!
drain() {
    kill -WINCH "$apache_pid" 2>/dev/null || true
    # Bound draining below the platform's 120-second termination budget.
    (sleep 105; kill -TERM "$apache_pid" 2>/dev/null || true) &
    timer_pid=$!
    wait "$apache_pid" || true
    kill "$timer_pid" 2>/dev/null || true
    wait "$timer_pid" 2>/dev/null || true
    exit 0
}
trap drain TERM INT
wait "$apache_pid"
