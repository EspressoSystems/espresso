let
  rustOverlay = import (builtins.fetchTarball "https://codeload.github.com/oxalica/rust-overlay/tar.gz/master");
  pkgs = import (builtins.fetchTarball "channel:nixos-21.11") { overlays = [ rustOverlay ]; };

  rustVersion = "1.57.0";
  rustPackages = pkgs.rust-bin.stable.${rustVersion}.default.override {
    extensions = [ "rust-src" ];
  };

in pkgs.mkShell {
  buildInputs =  with pkgs; [
    binutils-unwrapped
    curl
    git
    libiconv
    openssl
    pkgconfig
    rustPackages
  ] ++ lib.optionals stdenv.isDarwin [
    darwin.apple_sdk.frameworks.Security
  ];
  RUST_SRC_PATH = "${pkgs.rust-bin.stable.${rustVersion}.rust-src}/lib/rustlib/src/rust/library";
  RUST_BACKTRACE = 1;
}
