{
  description = "Simple Rust development environment template";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
  }:
    flake-utils.lib.eachDefaultSystem (system: let
      pkgs = import nixpkgs {inherit system;};

      # Native dependencies if needed
      buildInputs = with pkgs; [
        # Add libraries your project depends on if needed
        # openssl
      ];
    in {
      # Development shell
      devShells.default = pkgs.mkShell {
        # Just the standard Rust toolchain from nixpkgs
        packages = with pkgs; [
          rustc
          cargo
          rustfmt
          clippy
          rust-analyzer
          libpcap
        ];

        inherit buildInputs;

        # Basic environment setup
        RUST_BACKTRACE = 1;

        shellHook = ''
          echo "🦀 Rust development environment loaded"
          echo "Rust version: $(rustc --version)"
          echo "Cargo version: $(cargo --version)"
        '';
      };

      # Build package
      packages.default = pkgs.rustPlatform.buildRustPackage {
        pname = "my-rust-project";
        version = "0.1.0";
        src = ./.;

        cargoLock = {
          lockFile = ./Cargo.lock;
        };
      };
    });
}
