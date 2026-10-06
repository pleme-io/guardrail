{ rulesDir, genericSuites }:
{
  cfg,
  pkgs,
  lib,
  config,
}:
let
  r = import ./render.nix {
    inherit lib pkgs;
    inherit (cfg) package;
  } cfg;
in
{
  assertions = map (n: {
    assertion = false;
    message = "blackmatter.components.claude.guardrail.ruleSuites.${n}: set exactly one of `source` and `rules`.";
  }) r.suiteProblems;

  blackmatter.components.claude.guardrail = {
    ruleSuites = lib.genAttrs genericSuites (n: {
      source = lib.mkDefault "${rulesDir}/${n}.yaml";
    });
    checkTools = r.checkTools;
    hookRegistrations = r.hookRegistrations;
  };

  home.file = {
    ".config/guardrail/guardrail.yaml".source = "${r.gated}/guardrail.yaml";
  }
  // lib.mapAttrs' (
    n: _: lib.nameValuePair ".config/guardrail/rules.d/${n}.yaml" { source = "${r.gated}/rules.d/${n}.yaml"; }
  ) r.suites;

  home.activation.guardrail-compile = lib.hm.dag.entryAfter [ "writeBoundary" ] ''
    run ${cfg.package}/bin/guardrail compile
  '';
}
