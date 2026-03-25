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
      # keep-sorted start block=yes newline_separated=yes
      alejandra = {
        enable = true;

        priority = 100;
      };

      deadnix.enable = true;

      keep-sorted.enable = true;

      statix.enable = true;
      # keep-sorted end
    };
  };

  git-hooks.hooks = {
    # keep-sorted start block=yes newline_separated=yes
    check-merge-conflicts = {
      enable = true;

      fail_fast = true; # abort immediately so treefmt never runs on conflicted files
    };

    end-of-file-fixer.enable = true;

    flake-checker.enable = true;

    mixed-line-endings = {
      enable = true;

      args = [
        # keep-sorted start
        # force LF line endings
        "--fix=lf"
        # keep-sorted end
      ];
    };

    shellcheck.enable = true;

    treefmt = {
      enable = true;

      after = [
        # keep-sorted start
        "check-merge-conflicts"
        # keep-sorted end
      ];
    };

    trim-trailing-whitespace = {
      enable = true;

      args = [
        # keep-sorted start
        "--markdown-linebreak-ext=md" # preserve markdown hard linebreaks (https://github.github.com/gfm/#hard-line-break)
        # keep-sorted end
      ];
    };
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
