{
  # keep-sorted start
  config,
  lib,
  # keep-sorted end
  ...
}: {
  scripts = {
    # keep-sorted start
    du.exec = "devenv update";
    nfc.exec = "nix flake check";
    nfl.exec = "nix flake lock";
    nfu.exec = "nix flake update";
    ua.exec = "${lib.getExe config.scripts.du.scriptPackage} && ${lib.getExe config.scripts.nfu.scriptPackage}";
    # keep-sorted end
  };

  languages = {
    # keep-sorted start
    c.enable = true;
    nix.enable = true;
    # keep-sorted end
  };

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

      # force LF line endings
      args = ["--fix=lf"];
    };

    shellcheck = {
      enable = true;

      # produces false positives on zsh
      excludes = ["\\.zsh$"];
    };

    treefmt = {
      enable = true;

      after = ["check-merge-conflicts"];
    };

    trim-trailing-whitespace = {
      enable = true;

      # preserve markdown hard linebreaks (https://github.github.com/gfm/#hard-line-break)
      args = ["--markdown-linebreak-ext=md"];
    };
    # keep-sorted end
  };

  devcontainer = {
    enable = true;

    settings = {
      # cache /nix between rebuilds
      mounts = ["source=devcontainer-nix,target=/nix,type=volume"];

      onCreateCommand = "sudo sh -c 'echo \"accept-flake-config = true\" >> /etc/nix/nix.conf'";

      customizations.vscode.extensions = [
        # keep-sorted start
        "EditorConfig.EditorConfig"
        "jnoortheen.nix-ide"
        "mkhl.direnv"
        "ms-vscode.cmake-tools"
        "ms-vscode.cpptools"
        # keep-sorted end
      ];
    };
  };
}
