let
  nixpkgs =
    fetchTarball
    "https://github.com/NixOS/nixpkgs/archive/ee09932cedcef15aaf476f9343d1dea2cb77e261.tar.gz";
  pkgs = import nixpkgs {
    config = {};
    overlays = [];
  };

  helpers = import (builtins.fetchTarball
    "https://github.com/loicsikidi/nix-shell-toolbox/tarball/main") {
    inherit pkgs;
    hooksConfig = {
      gotest.settings.flags = "-race";
    };
  };
in
  pkgs.mkShellNoCC {
    packages = with pkgs;
      [
        # required to run TPM simulator
        # source: https://github.com/google/go-tpm-tools/tree/main/simulator
        gcc
        openssl
      ]
      ++ helpers.packages;
    # we disable the hardening due to this error: https://github.com/tpm2-software/tpm2-tools/issues/1561
    # fix found here: https://github.com/NixOS/nixpkgs/issues/18995#issuecomment-249748307
    hardeningDisable = ["fortify"];

    shellHook = ''
      ${helpers.shellHook}
      echo "Development environment ready!"
      echo "  - Go version: $(go version)"
    '';

    env = {
      CGO_ENABLED = "1";

      # Disable warnings from TPM simulator C code
      CGO_CFLAGS = "-Wno-array-bounds -Wno-stringop-overflow";
    };
  }
