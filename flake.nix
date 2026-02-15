{
  description = "Tempo Hackathon - Hello World Rust Project";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
      flake-utils,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        overlays = [
          (import rust-overlay)
        ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };

        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [
            "rust-src"
            "rust-analyzer"
          ];
        };

        nativeBuildInputs = with pkgs; [
          rustToolchain
          pkg-config
          just
          protobuf
          protoc-gen-prost
          protoc-gen-tonic
          mdbook
          mdbook-mermaid
          coreutils
          findutils
          gawk
          gnused
        ];

        buildInputs =
          with pkgs;
          [ ]
          ++ lib.optionals stdenv.isDarwin [
            libiconv
          ];

      in
      {
        devShells.default = pkgs.mkShell {
          inherit nativeBuildInputs buildInputs;

          shellHook = ''
            echo "Tempo Hackathon development environment"
            echo "Rust: $(rustc --version)"
            echo "Protoc: $(protoc --version)"
          '';
        };

        packages.default = pkgs.rustPlatform.buildRustPackage {
          pname = "tempo-hackathon";
          version = "0.1.0";

          src = ./.;

          cargoLock = {
            lockFile = ./Cargo.lock;
          };

          inherit nativeBuildInputs buildInputs;

          meta = with pkgs.lib; {
            description = "Tempo Hackathon - Hello World Rust Project";
            license = licenses.mit;
          };
        };
      }
    );
}
