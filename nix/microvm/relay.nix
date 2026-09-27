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
}
