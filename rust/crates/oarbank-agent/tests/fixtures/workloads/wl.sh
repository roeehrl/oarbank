#!/bin/sh
# A synthetic workload for the agent's tests: its leader starts a daemon that calls setsid and forks twice (so it
# leaves the leader's process group and session), tries to listen (the sandbox refuses), then stays in the
# foreground until the control document asks it to stop.
case "$1" in
run)
  cd "$OARBANK_WORKLOAD_RUN" || exit 70
  /usr/bin/perl -MIO::Socket::INET -e 'my $s = IO::Socket::INET->new(LocalAddr => "127.0.0.1", LocalPort => 0, Listen => 1);
    print $s ? "listening\n" : "refused: $!\n"' > listen.txt 2>&1
  /usr/bin/perl -MPOSIX -e 'exit 0 if fork; POSIX::setsid(); exit 0 if fork;
    open(my $f, ">", "daemon.pid.tmp") or die; print $f "$$\n"; close $f; rename "daemon.pid.tmp", "daemon.pid";
    while (1) { open(my $h, ">>", "beats") or die; print $h time, "\n"; close $h; sleep 1 }'
  echo '{"type": "progress", "event": "started"}' >> "$OARBANK_EVENTS_FILE"
  while :; do
    if grep -q '"stop":true' "$OARBANK_CONTROL_FILE" 2>/dev/null; then exit 0; fi
    sleep 0.2
  done ;;
status)
  echo '{"healthy": true, "detail": "ok"}' ;;
*)
  exit 64 ;;
esac
