{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
  };

  outputs = inputs @ {
    flake-parts,
    self,
    ...
  }:
    flake-parts.lib.mkFlake {inherit inputs;} {
      systems = ["i686-linux"];

      perSystem = {
        pkgs,
        lib,
        ...
      }: {
        packages.default = pkgs.stdenv.mkDerivation {
          pname = "cstrike-mod";
          version = "0-unstable-${lib.substring 0 8 self.lastModifiedDate}";

          src = ./.;

          nativeBuildInputs = [pkgs.cmake];

          installPhase = ''
            mkdir -p $out/lib

            cp libcstrike_mod.so $out/lib/
          '';

          meta = {
            description = "Client-side modification library for Counter-Strike";
            homepage = "https://github.com/hilorioze/cstrike-mod";
            license = lib.licenses.unfree;
            platforms = ["i686-linux"];
          };
        };
      };
    };
}
