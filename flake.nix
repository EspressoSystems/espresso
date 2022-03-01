{
  description = "A devShell example";

  inputs.nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";

  inputs.flake-utils.url = "github:numtide/flake-utils";

  inputs.flake-compat.url = "github:edolstra/flake-compat";
  inputs.flake-compat.flake = false;

  inputs.rust-overlay.url = "github:oxalica/rust-overlay";

  outputs =
    { self
    , nixpkgs
    , flake-utils
    , flake-compat
    , rust-overlay
    , ...
    }:
    flake-utils.lib.eachDefaultSystem (system:
    let
      overlays = [ (import rust-overlay) ];
      pkgs = import nixpkgs {
        inherit system overlays;
      };
    in
    {
      devShell =
        let

          stableToolchain = pkgs.rust-bin.stable."1.58.1".minimal.override {
            extensions = [ "rustfmt" "clippy" "llvm-tools-preview" "rust-src" ];
          };
          rustDeps = with pkgs; [
            pkgconfig
            openssl

            curl
            stableToolchain

            cargo-edit
            cargo-udeps
          ] ++ lib.optionals stdenv.isDarwin [
            # required to compile ethers-rs
            darwin.apple_sdk.frameworks.Security
            darwin.apple_sdk.frameworks.CoreFoundation

            # https://github.com/NixOS/nixpkgs/issues/126182
            libiconv
          ] ++ lib.optionals (stdenv.system != "aarch64-darwin") [
            cargo-watch # broken: https://github.com/NixOS/nixpkgs/issues/146349
          ];
          # nixWithFlakes allows pre v2.4 nix installations to use
          # flake commands (like `nix flake update`)
          nixWithFlakes = pkgs.writeShellScriptBin "nix" ''
            exec ${pkgs.nixFlakes}/bin/nix --experimental-features "nix-command flakes" "$@"
          '';
        in
        pkgs.mkShell
          {
            buildInputs = with pkgs; [
              nixWithFlakes
              nixpkgs-fmt
              git
              mdbook # make-doc, documentation generation
            ]
            ++ rustDeps;

            RUST_SRC_PATH = "${stableToolchain}/lib/rustlib/src/rust/library";
            RUST_BACKTRACE = 1;
            RUST_LOG = "info";
          };

    }
    );
}

