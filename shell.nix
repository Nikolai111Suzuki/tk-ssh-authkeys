with import (builtins.fetchTarball "https://d3g5gsiof5omrk.cloudfront.net/nixos/unstable-small/nixos-18.03pre119946.b8abd97c3b/nixexprs.tar.xz") {};

stdenv.mkDerivation rec {
  name = "tk-ssh-agent-env";
  env = buildEnv { name = name; paths = buildInputs; };

  buildInputs = [
    go
    upx
    gocode
    golint
    go-ethereum
  ]  ++ (if stdenv.isLinux then [
    # Packaging tools
    python3
    fpm
    rpm
  ] else []);
}
