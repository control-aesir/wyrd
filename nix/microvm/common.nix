# nix/microvm/common.nix — shared base for every wyrd microVM guest.
# Fully provisioned at build time: the bridge network has no uplink,
# so guests cannot fetch anything after boot (no `nix profile add`
# inside). The wyrd binary rides the closure too (see the inline
# module in flake.nix): the host store is not visible in-guest, and
# the same content-addressed path serves both sides.
{ config, pkgs, lib, ... }:
{
  options.wyrd = {
    # Host directory shared into every guest at /mnt/wyrd-state:
    # drive dirs (stateful across runs), the runner-generated
    # e2e-env.sh, and log collection. Must match run-microvm.sh's
    # --state-dir default.
    stateDir = lib.mkOption {
      type = lib.types.str;
      default = "/var/lib/wyrd-microvm/state";
      description = "Host path shared into guests at /mnt/wyrd-state.";
    };
  };

  config = {
    # Deterministic interface names: with one NIC per guest this is
    # always eth0, so the suite throttles and addresses one name.
    boot.kernelParams = [ "net.ifnames=0" ];

    # The test bridge is isolated (no uplink, host-only): filtering
    # there buys nothing and breaks the relay port plus dynamic iroh
    # UDP between peers. The VM boundary is the isolation.
    networking.firewall.trustedInterfaces = [ "eth0" ];

    # The spike proved /dev/fuse is rw under the default microvm
    # kernel; no extra kernel modules needed. The suite fails loudly
    # at first mount if that ever regresses.
    environment.systemPackages = with pkgs; [
      python3Minimal
      jq
      iproute2
      fuse3
      sudo
      procps
    ];
    security.sudo.enable = true;
    # The suite runs as e2e, mirroring the Lima guest's unprivileged
    # user: step 1's credential-hardening negatives (wrong owner,
    # group-readable) only mean anything as non-root. Passwordless
    # sudo covers the suite's `sudo tc` / `sudo chown` calls.
    # /dev/fuse is 0666 via systemd's default udev rules, and the
    # setuid fusermount wrapper below lets e2e mount.
    users.users.e2e = {
      isNormalUser = true;
      extraGroups = [ "wheel" ];
    };
    security.sudo.extraRules = [{
      users = [ "e2e" ];
      commands = [{ command = "ALL"; options = [ "NOPASSWD" ]; }];
    }];
    programs.fuse.userAllowOther = true;

    # The suite rides the image, not a share: guests have no uplink,
    # so nothing can be fetched after boot. Paths are relative to
    # this file (nix/microvm/) into the repo's tests/.
    environment.etc = {
      "wyrd-tests/alpha-common.sh".source = ../../tests/alpha-common.sh;
      "wyrd-tests/alpha-lima.sh".source = ../../tests/alpha-lima.sh;
      "wyrd-tests/alpha-microvm-legs.sh".source = ../../tests/alpha-microvm-legs.sh;
      "wyrd-tests/alpha-lima-matrix.py".source = ../../tests/alpha-lima-matrix.py;
    };

    services.openssh = {
      enable = true;
      settings.PermitRootLogin = "prohibit-password";
    };
    # Root login is key-only; the key itself arrives per boot, never
    # baked: `wyrd-ssh-key.service` below copies the runner-generated
    # pubkey from the state share into place, so image builds carry
    # no credentials and rotation is just a new run.
    users.users.root.openssh.authorizedKeys.keys = [ ];

    # Boot-time ssh key install from the state share, for root and
    # the e2e suite user. Poll-wait instead of ordering on the
    # virtiofs mount unit: robust regardless of mount timing, and
    # the host retries ssh anyway.
    systemd.services.wyrd-ssh-key = {
      wantedBy = [ "multi-user.target" ];
      script = ''
        for i in $(seq 1 150); do
          [ -f /mnt/wyrd-state/ssh_host_key.pub ] && break
          sleep 0.2
        done
        mkdir -p /root/.ssh /home/e2e/.ssh
        cp /mnt/wyrd-state/ssh_host_key.pub /root/.ssh/authorized_keys
        cp /mnt/wyrd-state/ssh_host_key.pub /home/e2e/.ssh/authorized_keys
        chmod 600 /root/.ssh/authorized_keys /home/e2e/.ssh/authorized_keys
        chown -R e2e:users /home/e2e/.ssh
      '';
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
      };
    };

    microvm = {
      hypervisor = "qemu";
      shares = [{
        proto = "virtiofs";
        tag = "wyrd-state";
        source = config.wyrd.stateDir;
        mountPoint = "/mnt/wyrd-state";
      }];
    };

    system.stateVersion = "26.05";
  };
}
