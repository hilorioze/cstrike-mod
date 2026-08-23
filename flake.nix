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
    # keep-sorted start block=yes newline_separated=yes
    dobby = {
      url = "github:jmpews/Dobby/b0176de574104726bb68dff3b77ee666300fc338";

      flake = false;
    };

    flake-parts.url = "github:hercules-ci/flake-parts";
    # keep-sorted end

    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
  };

  outputs = inputs @ {
    # keep-sorted start
    dobby,
    flake-parts,
    nixpkgs,
    # keep-sorted end
    ...
  }: let
    systems = ["i686-linux"];

    cstrike-mod = {
      # keep-sorted start
      cmake,
      dobby,
      lib,
      libGL,
      stdenv,
      # keep-sorted end
      ...
    }:
      stdenv.mkDerivation {
        pname = "cstrike-mod";

        version = "0";

        src = lib.fileset.toSource {
          root = ./.;

          fileset = lib.fileset.unions [
            ./CMakeLists.txt
            ./dobby.nix
            ./src
          ];
        };

        nativeBuildInputs = [cmake];

        buildInputs = [
          # keep-sorted start
          dobby
          libGL
          # keep-sorted end
        ];

        installPhase = ''
          runHook preInstall

          install -D --mode=444 libcstrike_mod.so $out/lib/libcstrike_mod.so

          runHook postInstall
        '';

        meta = {
          description = "Client-side modification library for Counter-Strike";
          homepage = "https://github.com/hilorioze/cstrike-mod";

          license = lib.licenses.mit;

          platforms = systems;
        };
      };
  in
    flake-parts.lib.mkFlake {inherit inputs;} {
      inherit systems;

      perSystem = {system, ...}: let
        pkgs = import nixpkgs {inherit system;};

        dobbyPackage = pkgs.callPackage ./dobby.nix {src = dobby;};

        package = pkgs.callPackage cstrike-mod {dobby = dobbyPackage;};
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
