{
  lib,
  pkgs,
  package,
  homeManagerModule,
  hookEvents,
}:
let
  t = import ./types.nix { inherit lib hookEvents; };

  hmLib = lib // {
    hm.dag.entryAfter = _: text: { inherit text; };
  };

  pkgs' = pkgs.extend (_: _: { guardrail = package; });

  evaluate =
    fixture:
    (lib.evalModules {
      specialArgs.lib = hmLib;
      modules = [
        homeManagerModule
        {
          freeformType = lib.types.lazyAttrsOf lib.types.anything;
          _module.args.pkgs = pkgs';
        }
        { blackmatter.components.claude.guardrail = fixture; }
      ];
    }).config;

  rule = {
    name = "fixture-unscoped";
    pattern = "fixturecmd\\s+zap";
    severity = "block";
    message = "fixture";
    category = "fixture";
    window = "fixture-window";
    test_block = "fixturecmd zap";
    test_allow = "fixturecmd list";
    examples = {
      block = [ "fixturecmd zap all" ];
      allow = [ "fixturecmd zip" ];
    };
  };

  scoped = {
    name = "fixture-scoped";
    pattern = "^/fixture/secret";
    severity = "warn";
    message = "fixture";
    category = "fixture";
    tools = [
      "Write"
      "Read"
    ];
    field = "file_path";
    cwd = "^/work/";
    examples = {
      block = [
        {
          input = "/fixture/secret";
          cwd = "/work/a";
        }
        {
          input = "/fixture/secret/x";
          tool = "Read";
          cwd = "/work/b";
        }
      ];
      allow = [
        {
          input = "/fixture/secret";
          cwd = "/elsewhere";
        }
        {
          input = "/fixture/public";
          cwd = "/work/a";
        }
      ];
    };
  };

  fileSuite = pkgs.writeText "fixture-file.yaml" (
    builtins.toJSON [
      {
        name = "fixture-file-rule";
        pattern = "fixturecmd\\s+burn";
        severity = "block";
        message = "fixture";
        category = "fixture";
        test_block = "fixturecmd burn";
      }
    ]
  );

  fixture = {
    enable = true;
    categories.fixture-off = false;
    extraRules = [ rule ];
    ruleSuites = {
      fixture-typed.rules = [ scoped ];
      fixture-file.source = fileSuite;
      fixture-disabled = {
        enable = false;
        source = fileSuite;
      };
    };
    disabledRules = [ "fixture-disabled-rule" ];
    toolInputLimits = [
      {
        name = "fixture-limit";
        tools = [ "mcp__fixture__comment" ];
        field = "body";
        maxChars = 10;
        message = "short";
      }
    ];
    changeWindows = [
      {
        name = "FIX-1";
        tag = "fixture-window";
        start = "2026-01-01T00:00:00Z";
        end = "2026-01-02T00:00:00Z";
      }
    ];
    changeWindowFiles = [ "windows/fixture.json" ];
    prefilter = {
      extraCommands = [ "fixturecmd" ];
      removedCommands = [ "fixtureold" ];
      extraKeywords = [ "fixturekw" ];
      extraMarkers = [ "<<fixture>>" ];
    };
    hooks = {
      PreToolUse = [
        {
          action = "check";
          matcher = "Bash";
        }
        {
          action = "inputLimit";
          matcher = "mcp__fixture__comment";
        }
      ];
      PostToolUse = [
        {
          action = "searchAdvise";
          matcher = "Grep";
        }
        {
          action = "mintAdvise";
          matcher = "Bash";
        }
        { action = "searchNudge"; }
      ];
      Stop = [
        {
          action = "exec";
          command = [ "/usr/bin/true" ];
        }
      ];
    };
  };

  render =
    c:
    import ./render.nix {
      inherit lib package;
      pkgs = pkgs';
    } c.blackmatter.components.claude.guardrail;

  config = evaluate fixture;
  cfg = config.blackmatter.components.claude.guardrail;
  r = render config;

  renderedRules = r.yaml.extraRules ++ lib.concatMap (s: map r.renderRule s.rules) (lib.attrValues r.suites);
  examples = lib.concatMap (x: x.examples.block or [ ] ++ x.examples.allow or [ ]) renderedRules;
  keysOf = xs: lib.unique (lib.concatMap builtins.attrNames xs);
  sorted = xs: lib.sort lib.lessThan xs;

  coverage = {
    config = builtins.attrNames r.yaml;
    rule = keysOf renderedRules;
    examples = keysOf (map (x: x.examples) (lib.filter (x: x ? examples) renderedRules));
    exampleCall = keysOf (lib.filter builtins.isAttrs examples);
    toolInputLimit = keysOf r.yaml.toolInputLimits;
    changeWindow = keysOf r.yaml.changeWindows;
    prefilter = builtins.attrNames r.yaml.prefilter;
    actions = lib.unique (lib.concatMap (map (a: a.action)) (lib.attrValues r.yaml.hooks));
  };

  declared = {
    config = t.yamlKeys;
    rule = builtins.attrNames t.rule;
    examples = builtins.attrNames t.examples;
    exampleCall = builtins.attrNames t.exampleCall;
    toolInputLimit = builtins.attrNames t.toolInputLimit;
    changeWindow = builtins.attrNames t.changeWindow;
    prefilter = builtins.attrNames t.prefilter;
    inherit (t) actions;
  };

  uncovered = lib.filterAttrs (k: v: sorted v != sorted coverage.${k}) declared;

  expected = pkgs.writeText "guardrail-module-schema.json" (builtins.toJSON declared);

  payload =
    assert lib.assertMsg (uncovered == { })
      "nix/checks.nix: the fixture does not set every option; uncovered: ${builtins.toJSON uncovered}";
    assert lib.assertMsg (cfg.checkTools == [ "Bash" "Write" "Read" ])
      "nix/checks.nix: checkTools is ${builtins.toJSON cfg.checkTools}";
    assert lib.assertMsg (cfg.hookRegistrations == {
      PreToolUse = "Bash|mcp__fixture__comment";
      PostToolUse = null;
      Stop = null;
    }) "nix/checks.nix: hookRegistrations is ${builtins.toJSON cfg.hookRegistrations}";
    config.home.file.".config/guardrail/guardrail.yaml".source;

  rejected = expr: !(builtins.tryEval (builtins.deepSeq expr expr)).success;

  typoRule = removeAttrs rule [ "pattern" ] // { patern = rule.pattern; };

  brokenExample = rule // {
    name = "fixture-broken";
    examples.allow = [ "fixturecmd zap" ];
  };
in
{
  guardrail-module-roundtrip = pkgs.runCommand "guardrail-module-roundtrip" {
    nativeBuildInputs = [ package ];
  } ''
    guardrail schema --expect ${expected}
    cp ${payload} $out
  '';

  guardrail-module-refuses-a-misspelled-rule-key =
    assert lib.assertMsg (rejected (evaluate (fixture // { extraRules = [ typoRule ]; })).home.file)
      "a misspelled rule key evaluated";
    assert lib.assertMsg (rejected (evaluate (fixture // { extraRules = [ (rule // { severity = "deny"; }) ]; })).home.file)
      "an unknown severity evaluated";
    assert lib.assertMsg (rejected (evaluate (fixture // { categories.Fixture = false; })).home.file)
      "an uppercase category evaluated";
    pkgs.emptyFile;

  guardrail-module-refuses-a-broken-example = pkgs.testers.testBuildFailure (
    (render (evaluate (fixture // { extraRules = [ rule brokenExample ]; }))).gated
  );

  guardrail-validate-refuses-an-unknown-yaml-key = pkgs.testers.testBuildFailure (
    pkgs.runCommand "guardrail-unknown-key" { nativeBuildInputs = [ package ]; } ''
      mkdir -p cfg/guardrail
      printf 'extraRule: []\n' > cfg/guardrail/guardrail.yaml
      XDG_CONFIG_HOME=$PWD/cfg XDG_CACHE_HOME=$TMPDIR guardrail validate
      touch $out
    ''
  );
}
