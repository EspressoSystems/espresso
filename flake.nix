{
  description = "A devShell example";

  inputs.nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";

  inputs.flake-utils.url = "github:numtide/flake-utils";

  inputs.flake-compat.url = "github:edolstra/flake-compat";
  inputs.flake-compat.flake = false;

  inputs.rust-overlay.url = "github:oxalica/rust-overlay";

  outputs = { self, nixpkgs, flake-utils, flake-compat, rust-overlay, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { inherit system overlays; };
        stableToolchain = pkgs.rust-bin.stable."1.59.0".minimal.override {
          extensions = [ "rustfmt" "clippy" "llvm-tools-preview" "rust-src" ];
        };
        sixtyStableToolchain = pkgs.rust-bin.stable."1.60.0".minimal.override {
          extensions = [ "rustfmt" "clippy" "llvm-tools-preview" "rust-src" ];
        };
        stableMuslRustToolchain =
          pkgs.rust-bin.stable."1.59.0".minimal.override {
            extensions = [ "rustfmt" "clippy" "llvm-tools-preview" "rust-src" ];
            targets = [ "x86_64-unknown-linux-musl" ];
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
          localSystem = "x86_64-linux";
          crossSystem = { config = "x86_64-unknown-linux-musl"; };
        };
        muslRustDeps = with muslPkgs.pkgsStatic; [
          pkgconfig
          opensslMusl.dev
          opensslMusl.out
        ];
      in {
        devShell = pkgs.mkShell {
          buildInputs = with pkgs;
            [
              nixWithFlakes
              nixpkgs-fmt
              git
              mdbook # make-doc, documentation generation
              stableToolchain
            ] ++ rustDeps;

          RUST_SRC_PATH = "${stableToolchain}/lib/rustlib/src/rust/library";
          RUST_BACKTRACE = 1;
          RUST_LOG = "info";
        };
        devShells = {
          perfShell = pkgs.mkShell {
            buildInputs = with pkgs;
              [ cargo-llvm-cov sixtyStableToolchain ] ++ rustDeps;
          };
          staticShell = pkgs.mkShell {
            shellHook = ''
              export PATH=${pkgs.xdot}/bin:$PATH
            '';
            DEP_CURL_STATIC = "y";
            CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER =
              "${pkgs.llvmPackages_latest.lld}/bin/lld";
            RUSTFLAGS =
              "-C target-feature=+crt-static -L${opensslMusl.out}/lib/ -L${curlMusl.out}/lib -L${muslPkgs.pkgsStatic.zstd.out}/lib -L${muslPkgs.pkgsStatic.libssh2}/lib -L${muslPkgs.pkgsStatic.openssl}/lib -lssh2";
            OPENSSL_STATIC = "true";
            OPENSSL_DIR = "-L${muslPkgs.pkgsStatic.openssl}";
            OPENSSL_INCLUDE_DIR = "${opensslMusl.dev}/include/";
            OPENSSL_LIB_DIR = "${opensslMusl.dev}/lib/";
            CARGO_BUILD_TARGET = "x86_64-unknown-linux-musl";
            buildInputs = with pkgs;
              [ stableMuslRustToolchain fd ] ++ muslRustDeps;
          };
        };

      });
}
