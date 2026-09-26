# nix/microvm/peer-o.nix — owner peer: first writer, drive author.
{ ... }:
{
  networking.hostName = "wyrd-peer-o";
  networking.interfaces.eth0.ipv4.addresses =
    [{ address = "10.0.7.11"; prefixLength = 24; }];

  microvm = {
    vcpu = 4;
    mem = 4096;
    interfaces = [{
      type = "tap";
      id = "tap-o";
      mac = "02:00:00:00:07:11";
    }];
  };
}
