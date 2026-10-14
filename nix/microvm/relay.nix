# nix/microvm/relay.nix — control-plane relay as a VM service, always
# up for the run. The suite never manages it (RELAY_MANAGED=0): peer
# restarts are the test, relay restarts are not.
#
# The relay carries no runner ssh key: it serves the control plane
# only, and nothing ever logs into it. (It keeps the state share —
# the generated virtiofsd wrapper assumes at least one share, and
# the share contents are run-ephemeral test state. Peers keep both;
# see common.nix.)
{ pkgs, ... }:
{
  networking.hostName = "wyrd-relay";
  networking.interfaces.eth0.ipv4.addresses =
    [{ address = "10.0.7.10"; prefixLength = 24; }];

  systemd.services.wyrd-ssh-key.enable = false;

  microvm = {
    vcpu = 2;
    mem = 1024;
    interfaces = [{
      type = "tap";
      id = "tap-r";
      mac = "02:00:00:00:07:10";
    }];
  };

  environment.etc."wyrd-relay.toml".text = ''
    [info]
    relay_url = "ws://10.0.7.10:18761/"
    name = "wyrd-microvm"
    description = "microVM e2e relay; one run."

    [network]
    address = "0.0.0.0"
    port = 18761
  '';

  systemd.services.nostr-relay = {
    wantedBy = [ "multi-user.target" ];
    after = [ "network-online.target" ];
    wants = [ "network-online.target" ];
    serviceConfig = {
      ExecStart = "${pkgs.nostr-rs-relay}/bin/nostr-rs-relay -c /etc/wyrd-relay.toml -d /var/lib/wyrd-relay";
      Restart = "on-failure";
      StateDirectory = "wyrd-relay";
    };
  };

  # Relay-guest journal persistence for post-mortem forensics. The
  # 2026-10-08 ~30s relay flaps left no guest-side evidence: teardown
  # destroys the VM, and the relay carries no ssh key by design (see
  # above), so the host cannot pull logs out. A 60s timer overwrites
  # the current-boot journal into the state share, so the latest dump
  # is never more than a minute stale at teardown (AccuracySec=1s —
  # systemd's default 1min slop would make that bound a lie).
  # Overwrite, not append: bounded size, and the phase-1 pre-clean
  # wipes $RUN/logs once per run — the next tick recreates the file.
  # Ordered on the virtiofs mount, not merely timed: an early tick
  # before the mount is up would write onto the guest-local root and
  # the mount would hide it, failing invisibly in exactly the way
  # this unit exists to fix (same race common.nix's ssh-key unit
  # poll-waits around). The heartbeat timestamp next to the dump
  # distinguishes "relay logged nothing" from "the dump never ran" —
  # written only after a successful dump (via temp-file rename, so a
  # failed journalctl can never leave a fresh heartbeat over a
  # truncated log). Note the timestamp is guest-clock time (observed
  # ~11min ahead of the host on odin): cross-layer correlation
  # against host-availability.log must use the host-side file mtime
  # as the skew reference, never compare the two directly.
  systemd.services.wyrd-relay-journal = {
    after = [ "mnt-wyrd\\x2dstate.mount" ];
    requires = [ "mnt-wyrd\\x2dstate.mount" ];
    script = ''
      mkdir -p /mnt/wyrd-state/run/logs
      ${pkgs.systemd}/bin/journalctl -b --no-pager > /mnt/wyrd-state/run/logs/.relay-journal.tmp \
        && mv /mnt/wyrd-state/run/logs/.relay-journal.tmp /mnt/wyrd-state/run/logs/relay-journal.log \
        && date -u +%Y-%m-%dT%H:%M:%SZ > /mnt/wyrd-state/run/logs/relay-journal.ts
    '';
    serviceConfig = {
      Type = "oneshot";
      # A wedged journalctl stalls the oneshot and systemd skips
      # timer elapses while it runs — silently ending the dump
      # series. Bound the read instead.
      TimeoutStartSec = "30s";
    };
  };
  systemd.timers.wyrd-relay-journal = {
    wantedBy = [ "timers.target" ];
    timerConfig = {
      OnBootSec = "1min";
      OnUnitActiveSec = "1min";
      AccuracySec = "1s";
    };
  };
}
