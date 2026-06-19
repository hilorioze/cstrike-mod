{
  nixConfig = {
    # keep-sorted start block=yes newline_separated=yes
    extra-substituters = [
      # https://cache.nixos.org/ has priority 40
      "https://nix-cache.hilorioze.com?priority=41"
    ];

    extra-trusted-public-keys = ["nix-cache.hilorioze.com-1:vKKWGjVDgXl/TXbUWuPWTnDhhDit6hqkTcuoGfter5Y="];
    # keep-sorted end
  };

  inputs = {
    # keep-sorted start newline_separated=yes
    flake-parts.url = "github:hercules-ci/flake-parts";

    nix-filter.url = "github:numtide/nix-filter";
    # keep-sorted end

    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  };

  outputs = inputs @ {
    # keep-sorted start
    flake-parts,
    nix-filter,
    nixpkgs,
    # keep-sorted end
    ...
  }: let
    systems = ["i686-linux"];

    cstrike-mod = {
      # keep-sorted start
      cmake,
      lib,
      stdenv,
      # keep-sorted end
      ...
    }:
      stdenv.mkDerivation {
        pname = "cstrike-mod";

        version = "0";

        src = nix-filter.lib {
          root = ./.;

          include = [
            ./CMakeLists.txt
            ./src
          ];
        };

        nativeBuildInputs = [cmake];

        installPhase = ''
          runHook preInstall

          install -Dm444 libcstrike_mod.so $out/lib/libcstrike_mod.so

          runHook postInstall
        '';

        meta = {
          description = "Client-side modification library for Counter-Strike";
          homepage = "https://github.com/hilorioze/cstrike-mod";

          license = lib.licenses.unfree;

          platforms = systems;
        };
      };
  in
    flake-parts.lib.mkFlake {inherit inputs;} {
      inherit systems;

      perSystem = {system, ...}: let
        pkgs = import nixpkgs {
          inherit system;

          config.allowUnfree = true;
        };

        package = pkgs.callPackage cstrike-mod {};
      in {
        packages = {
          # keep-sorted start
          cstrike-mod = package;
          default = package;
          # keep-sorted end
        };
      };

      flake.overlays.default = _final: prev: inputs.self.packages.${prev.stdenv.hostPlatform.system} or {};
    };
}
