{
  description = "guardrail — defensive guardrails for AI coding agents";

  # Canonical pleme-io Rust-tool consumer flake. substrate.rust.tool
  # pre-binds nixpkgs / crate2nix / flake-utils / fenix / devenv / gen
  # — every dependency the build kit needs — so a substrate bump
  # propagates fleet-wide without touching this file. toolName + repo
  # are read from the typed `flake_metadata.guardrail` in
  # Cargo.build-spec.json.
  inputs.substrate.url = "github:pleme-io/substrate";

  outputs =
    { substrate, ... }:
    let
      lib = substrate.inputs.nixpkgs.lib;
      hookEvents = builtins.fromJSON (builtins.readFile ./hooks/events.json);
      genericSuites = [
        "aws"
        "aws-generated"
        "azure"
        "gcp"
        "network"
        "nosql"
        "process"
        "sql"
      ];
      tool = substrate.rust.tool {
        src = ./.;
        module = {
          description = "guardrail — defensive guardrails for AI coding agents";
          hmNamespace = "blackmatter.components.claude";
          extraHmOptions = l: (import ./nix/types.nix { lib = l; inherit hookEvents; }).options;
          extraHmConfigFn = import ./nix/hm.nix {
            rulesDir = ./rules;
            inherit genericSuites;
          };
        };
      };
    in
    tool
    // {
      checks = lib.mapAttrs (
        system: checks:
        checks
        // import ./nix/checks.nix {
          inherit lib hookEvents;
          pkgs = substrate.inputs.nixpkgs.legacyPackages.${system};
          package = tool.packages.${system}.default;
          homeManagerModule = tool.homeManagerModules.default;
        }
      ) tool.checks;
    };
}
