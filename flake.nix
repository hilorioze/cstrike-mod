{
  nixConfig = {
    # keep-sorted start block=yes newline_separated=yes
    extra-substituters = [
      "https://hilorioze.cachix.org"
    ];

    extra-trusted-public-keys = [
      "hilorioze.cachix.org-1:klg5Lbxx5LWqiNhBVd7gN9o5nL90PKLrQTyJD8QJUAo="
    ];
    # keep-sorted end
  };

  inputs = {
    # keep-sorted start
    flake-parts.url = "github:hercules-ci/flake-parts";
    # keep-sorted end

    # keep-sorted start
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    # keep-sorted end
  };

  outputs = inputs @ {
    # keep-sorted start
    flake-parts,
    nixpkgs,
    self,
    # keep-sorted end
    ...
  }: let
    systems = [
      # keep-sorted start
      "i686-linux"
      # keep-sorted end
    ];

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

        version = let
          date = self.lastModifiedDate;
        in "0-unstable-${lib.substring 0 4 date}-${lib.substring 4 2 date}-${lib.substring 6 2 date}";

        src = ./.;

        nativeBuildInputs = [
          # keep-sorted start
          cmake
          # keep-sorted end
        ];

        installPhase = ''
          runHook preInstall

          mkdir -p $out/lib

          cp libcstrike_mod.so $out/lib/

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
      imports = [
        # keep-sorted start
        flake-parts.flakeModules.easyOverlay
        # keep-sorted end
      ];

      inherit systems;

      perSystem = {
        # keep-sorted start
        system,
        # keep-sorted end
        ...
      }: let
        pkgs = import nixpkgs {
          inherit system;

          config.allowUnfree = true;
        };

        package = pkgs.callPackage cstrike-mod {};
      in {
        overlayAttrs.cstrike-mod = package;

        packages.default = package;
      };
    };
}
