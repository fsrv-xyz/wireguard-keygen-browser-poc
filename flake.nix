{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };

        devTools = with pkgs; [
          # Pinned to the go.mod directive; the nixpkgs default is still 1.26
          # and would pull a toolchain over the network instead.
          go_1_27
          gnumake
          # The root package is js/wasm only, so `make test` runs it under node.
          nodejs
          # Packs wg0.conf into serve/web/profile.zip.
          zip
        ];
      in
      {
        formatter = pkgs.nixfmt-tree;

        # Nothing here uses cgo, so the shell does without a C toolchain and
        # the environment it exports.
        devShells.default = pkgs.mkShellNoCC {
          packages = devTools;
          # An inherited GOROOT — GoLand exports the one of its configured SDK —
          # makes the go here compile against another release's tools.
          shellHook = "unset GOROOT";
        };
      }
    );
}
