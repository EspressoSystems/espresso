let
  nixpkgs = fetchTarball {
    url = "https://github.com/NixOS/nixpkgs/archive/a7ecde854aee5c4c7cd6177f54a99d2c1ff28a31.tar.gz";
    # To update hash:
    #   nix-prefetch-url --type sha256 --unpack https://github.com/NixOS/nixpkgs/archive/....tar.gz
    sha256 = "162dywda2dvfj1248afxc45kcrg83appjd0nmdb541hl7rnncf02";
  };
  moz_overlay = import (fetchTarball {
    url = "https://github.com/mozilla/nixpkgs-mozilla/archive/7c1e8b1dd6ed0043fb4ee0b12b815256b0b9de6f.tar.gz";
    sha256 = "1a71nfw7d36vplf89fp65vgj3s66np1dc0hqnqgj5gbdnpm1bihl";
  });
  NIGHTLY_DATE = "2021-08-01";
  pkgs = import nixpkgs { overlays = [ moz_overlay ]; };
  rustNightly = (pkgs.rustChannelOf { date = "${NIGHTLY_DATE}"; channel = "nightly"; }).rust.override {
    extensions = [
      "clippy-preview"
      "rustfmt-preview"
      "rust-src"
    ];
  };
in
with pkgs;
stdenv.mkDerivation {
  name = "rust-env";
  buildInputs = [
    # Note: to use use stable, just replace `nightly` with `stable`
    rustNightly

    # Add some extra dependencies from `pkgs`
    openssl
    pkgconfig
    openssl
    binutils-unwrapped
    cargo-udeps
    libiconv
    curl

    alloy5
  ] ++ lib.optionals stdenv.isDarwin [
    darwin.apple_sdk.frameworks.Security
  ];

  # Set Environment Variables
  RUST_BACKTRACE = 1;

  shellHook = ''
    export PATH="$PATH:./target/debug"
  '';
}
