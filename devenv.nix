{
  # keep-sorted start
  lib,
  pkgs,
  # keep-sorted end
  ...
}: {
  scripts = {
    # keep-sorted start
    du.exec = "${lib.getExe pkgs.devenv} update";
    nfc.exec = "${lib.getExe pkgs.nix} flake check";
    nfl.exec = "${lib.getExe pkgs.nix} flake lock";
    nfu.exec = "${lib.getExe pkgs.nix} flake update";
    ua.exec = "du && nfu";
    # keep-sorted end
  };

  languages.c.enable = true;

  treefmt = {
    enable = true;

    config.programs = {
      # keep-sorted start
      deadnix.enable = true;
      keep-sorted.enable = true;
      # keep-sorted end
    };

    config.settings.formatter.alejandra = {
      command = lib.getExe pkgs.alejandra;
      includes = [
        # keep-sorted start
        "*.nix"
        # keep-sorted end
      ];
    };
  };

  git-hooks.hooks = {
    # keep-sorted start
    end-of-file-fixer.enable = true;
    mixed-line-endings.enable = true;
    treefmt.enable = true;
    trim-trailing-whitespace.enable = true;
    # keep-sorted end
  };

  devcontainer = {
    enable = true;

    settings.customizations.vscode.extensions = [
      # keep-sorted start
      "EditorConfig.EditorConfig"
      "jnoortheen.nix-ide"
      "mkhl.direnv"
      "ms-vscode.cmake-tools"
      "ms-vscode.cpptools"
      # keep-sorted end
    ];
  };
}
