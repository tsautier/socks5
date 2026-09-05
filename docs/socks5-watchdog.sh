#!/bin/sh
# Cron watchdog for Simple Socks5: start it if it is not already running.
#
# Install (as root):
#   cp docs/socks5-watchdog.sh /opt/socks5/watchdog.sh
#   chmod 755 /opt/socks5/watchdog.sh
#
# Then add to root's crontab (crontab -e):
#   * * * * * /opt/socks5/watchdog.sh >/dev/null 2>&1
#
# The redirect matters. socks5 daemonises with noclose=1, so it inherits cron's
# stdout/stderr; without the redirect cron holds the pipe open and mails you on
# every run.
#
# NOTE: this only works with a PLAINTEXT config. An encrypted one prompts for
# the Blowfish key on a terminal, which cron cannot answer.

set -u

DIR=/opt/socks5
BIN="$DIR/socks5"
CONF="$DIR/socks5.conf"
PIDFILE="$DIR/socks5.pid"
LOCK="$DIR/.watchdog.lock"
LOG="$DIR/watchdog.log"

# Serialise against an overlapping run, so two cron ticks cannot both start the
# daemon. Re-exec under flock if it is available.
if [ "${WATCHDOG_LOCKED:-}" != "1" ] && command -v flock >/dev/null 2>&1; then
    WATCHDOG_LOCKED=1
    export WATCHDOG_LOCKED
    exec flock -n "$LOCK" "$0" "$@"
fi

log() { echo "$(date '+%Y-%m-%d %H:%M:%S') $*" >> "$LOG"; }

running() {
    [ -f "$PIDFILE" ] || return 1
    pid=$(cat "$PIDFILE" 2>/dev/null)
    # must be a plain number
    case "$pid" in
        ''|*[!0-9]*) return 1 ;;
    esac
    [ -d "/proc/$pid" ] || return 1
    # Guard against PID reuse: the pid must actually be our socks5, not some
    # unrelated process that happens to have inherited that number.
    [ "$(cat "/proc/$pid/comm" 2>/dev/null)" = "socks5" ] || return 1
    return 0
}

if running; then
    exit 0
fi

cd "$DIR" || { log "ERROR: cannot cd to $DIR"; exit 1; }

if [ ! -x "$BIN" ]; then
    log "ERROR: $BIN is missing or not executable"
    exit 1
fi
if [ ! -r "$CONF" ]; then
    log "ERROR: $CONF is missing or unreadable"
    exit 1
fi

# Stale pidfile from a crash, or a first start.
[ -f "$PIDFILE" ] && log "stale pidfile (pid $(cat "$PIDFILE" 2>/dev/null)) - restarting"

"$BIN" -u "$CONF" >/dev/null 2>&1
rc=$?
if [ $rc -ne 0 ]; then
    log "ERROR: socks5 exited with status $rc on start"
    exit 1
fi

# socks5 forks, so give it a moment to write the pidfile before confirming.
sleep 1
if running; then
    log "started (pid $(cat "$PIDFILE"))"
else
    log "ERROR: started but no live pid in $PIDFILE - check the socks5 debug log"
    exit 1
fi
