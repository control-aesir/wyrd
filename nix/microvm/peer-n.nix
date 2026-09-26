# nix/microvm/peer-n.nix — member peer: joins via invitation, converges
# over the relay, exercises fetch-on-open demand across hosts.
{ ... }:
{
  networking.hostName = "wyrd-peer-n";
  networking.interfaces.eth0.ipv4.addresses =
    [{ address = "10.0.7.12"; prefixLength = 24; }];

  microvm = {
    vcpu = 4;
    mem = 4096;
    interfaces = [{
      type = "tap";
      id = "tap-n";
      mac = "02:00:00:00:07:12";
    }];
  };
}
