# Copyright (c) 2022 Espresso Systems (espressosys.com)
# This file is part of the Espresso library.
#
# This program is free software: you can redistribute it and/or modify it under the terms of the GNU
# General Public License as published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
# You should have received a copy of the GNU General Public License along with this program. If not,
# see <https://www.gnu.org/licenses/>.

{
  description = "A devShell example";

  nixConfig = {
    extra-substituters = ["https://espresso-systems-private.cachix.org"];
    extra-trusted-public-keys = ["espresso-systems-private.cachix.org-1:LHYk03zKQCeZ4dvg3NctyCq88e44oBZVug5LpYKjPRI="];
  };

  inputs.nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";

  inputs.flake-utils.url = "github:numtide/flake-utils";

  inputs.flake-compat.url = "github:edolstra/flake-compat";
  inputs.flake-compat.flake = false;

  inputs.rust-overlay.url = "github:oxalica/rust-overlay";

  inputs.pre-commit-hooks.url = "github:cachix/pre-commit-hooks.nix";
  # See https://github.com/cachix/pre-commit-hooks.nix/pull/122
  inputs.pre-commit-hooks.inputs.flake-utils.follows = "flake-utils";
  inputs.pre-commit-hooks.inputs.nixpkgs.follows = "nixpkgs";

  inputs.fenix.url = "github:nix-community/fenix";
  inputs.fenix.inputs.nixpkgs.follows = "nixpkgs";

  outputs = { self, nixpkgs, flake-utils, flake-compat, rust-overlay, pre-commit-hooks, fenix, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        info = builtins.split "\([a-zA-Z0-9_]+\)" system;
        arch = (builtins.elemAt (builtins.elemAt info 1) 0);
        os = (builtins.elemAt (builtins.elemAt info 3) 0);
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { inherit system overlays; };
        rust_version = "1.64.0";
        stableToolchain = pkgs.rust-bin.stable.${rust_version}.minimal.override {
          extensions = [ "rustfmt" "clippy" "llvm-tools-preview" "rust-src" ];
        };
        stableMuslRustToolchain =
          pkgs.rust-bin.stable.${rust_version}.minimal.override {
            extensions = [ "rustfmt" "clippy" "llvm-tools-preview" "rust-src" ];
            targets = [ "${arch}-unknown-${os}-musl" ];
        };
        rustDeps = with pkgs;
          [
            pkgconfig
            openssl
            bash

            curl

            cargo-edit
            cargo-udeps
            cargo-sort
            cmake
          ] ++ lib.optionals stdenv.isDarwin [
            # required to compile ethers-rs
            darwin.apple_sdk.frameworks.Security
            darwin.apple_sdk.frameworks.CoreFoundation
            darwin.apple_sdk.frameworks.SystemConfiguration

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
        cargo-llvm-cov = pkgs.rustPlatform.buildRustPackage rec {
          pname = "cargo-llvm-cov";
          version = "0.3.0";

          doCheck = false;

          buildInputs = [ pkgs.libllvm ];

          src = builtins.fetchTarball {
            url =
              "https://crates.io/api/v1/crates/${pname}/${version}/download";
            sha256 =
              "sha256:0iswa2cdaf2123vfc42yj9l8jx53k5jm2y51d4xqc1672hi4620l";
          };

          cargoSha256 = "sha256-RzIkW/eytU8ZdZ18x0sGriJ2xvjVW+8hB85In12dXMg=";
          meta = with pkgs.lib; {
            description = "Cargo llvm cov generates code coverage via llvm.";
            homepage = "https://github.com/taiki-e/cargo-llvm-cov";

            license = with licenses; [ mit asl20 ];
          };
        };
        opensslMusl = muslPkgs.openssl.override { static = true; };
        curlMusl = (muslPkgs.pkgsStatic.curl.override {
          http2Support = false;
          libssh2 = muslPkgs.pkgsStatic.libssh2.dev;
          zstdSupport = false;
          idnSupport = false;
        }).overrideAttrs (oldAttrs:
          let confFlags = oldAttrs.configureFlags;
          in {
            configureFlags = (muslPkgs.lib.take 13 confFlags)
              ++ (muslPkgs.lib.drop 14 confFlags)
              ++ [ (muslPkgs.lib.withFeature true "libssh2") ];
          });
        # MUSL pkgs
        muslPkgs = import nixpkgs {
          localSystem = system;
          crossSystem = { config = "${arch}-unknown-${os}-musl"; };
        };
        pythonEnv = pkgs.poetry2nix.mkPoetryEnv { projectDir = ./.; };
        myPython = with pkgs; [ poetry pythonEnv ];
        shellHook  = ''
          # on mac os `bin/pwd -P` returns the canonical path on case insensitive file-systems
          my_pwd=$(/bin/pwd -P 2> /dev/null || pwd)

          export PATH=${pkgs.xdot}/bin:$PATH
          export PATH=''${my_pwd}/bin:$PATH

          # Prevent cargo aliases from using programs in `~/.cargo` to avoid conflicts
          # with rustup installations.
          export CARGO_HOME=$HOME/.cargo-nix
        '';
      in {
        checks = {
          pre-commit-check = pre-commit-hooks.lib.${system}.run {
            src = ./.;
            hooks = {
              cargo-fmt = {
                enable = true;
                description = "Enforce rustfmt";
                entry = "cargo fmt --all -- --check";
                pass_filenames = false;
              };
              cargo-sort = {
                enable = true;
                description = "Ensure Cargo.toml are sorted";
                entry = "cargo sort -g -w -c";
                pass_filenames = false;
              };
              cargo-clippy = {
                enable = true;
                description = "Run clippy";
                entry = "cargo clippy --workspace -- -D clippy::dbg-macro";
                pass_filenames = false;
              };
              license-header-c-style = {
                enable = true;
                description =
                  "Ensure files with c-style comments have license header";
                entry = ''
                  insert_license --license-filepath .license-header.txt  --comment-style "//"'';
                types_or = [ "rust" ];
                pass_filenames = true;
              };
              license-header-hash = {
                enable = true;
                description =
                  "Ensure files with hash style comments have license header";
                entry = ''
                  insert_license --license-filepath .license-header.txt --comment-style "#"'';
                types_or = [ "bash" "python" "toml" "nix" ];
                excludes = [ "poetry.lock" ];
                pass_filenames = true;
              };
              license-header-html = {
                enable = true;
                description = "Ensure markdown files have license header";
                entry = ''
                  insert_license --license-filepath .license-header.txt --comment-style "<!--| ~| -->"'';
                types_or = [ "markdown" ];
                pass_filenames = true;
              };
            };
          };
        };
        devShell = pkgs.mkShell {
          shellHook = shellHook
            # install pre-commit hooks
            + self.checks.${system}.pre-commit-check.shellHook;
          buildInputs = with pkgs;
            [
              fenix.packages.${system}.rust-analyzer
              nixWithFlakes
              nixpkgs-fmt
              protobuf
              git
              mdbook # make-doc, documentation generation
              stableToolchain
            ] ++ myPython ++ rustDeps;

          RUST_SRC_PATH = "${stableToolchain}/lib/rustlib/src/rust/library";
          RUST_BACKTRACE = 1;
          RUST_LOG = "info,libp2p=off";
        };
        devShells = {
          perfShell = pkgs.mkShell {
            shellHook = shellHook;
            buildInputs = with pkgs;
              [ cargo-llvm-cov stableToolchain protobuf ] ++ rustDeps;

            RUST_LOG = "info,libp2p=off";
            ESPRESSO_FAUCET_TEST_DISABLE_TIMEOUT = "1";
            SEAHORSE_TEST_TXN_HISTORY_TIME_TOLERANCE = "30";
            ESPRESSO_CLI_TEST_CONNECTION_TIMEOUT = "30m";
          };

          staticShell = pkgs.mkShell {
            shellHook = shellHook;
            DEP_CURL_STATIC = "y";
            "CARGO_TARGET_${pkgs.lib.toUpper arch}_UNKNOWN_${pkgs.lib.toUpper os}_MUSL_LINKER" =
              "${pkgs.llvmPackages_latest.lld}/bin/lld";
            RUSTFLAGS =
              "-C target-feature=+crt-static -L${opensslMusl.out}/lib/ -L${curlMusl.out}/lib -L${muslPkgs.pkgsStatic.zstd.out}/lib -L${muslPkgs.pkgsStatic.libssh2}/lib -L${muslPkgs.pkgsStatic.openssl}/lib -lssh2";
            OPENSSL_STATIC = "true";
            OPENSSL_DIR = "-L${muslPkgs.pkgsStatic.openssl}";
            OPENSSL_INCLUDE_DIR = "${opensslMusl.dev}/include/";
            OPENSSL_LIB_DIR = "${opensslMusl.dev}/lib/";
            CARGO_BUILD_TARGET = "${arch}-unknown-${os}-musl";
            buildInputs = with pkgs;
              [ protobuf stableMuslRustToolchain fd cmake ];
            meta.broken = if "${os}" == "darwin" then true else false;

            RUST_LOG = "info,libp2p=off";
          };
        };

      });
}
