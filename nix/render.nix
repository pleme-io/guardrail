{ lib, pkgs, package }:
cfg:
let
  prune = lib.filterAttrs (_: v: v != null && v != [ ] && v != { });

  renderExample = e: if builtins.isString e then e else prune e;

  renderRule =
    r:
    prune (
      removeAttrs r [ "examples" ]
      // {
        examples = prune (lib.mapAttrs (_: map renderExample) r.examples);
      }
    );

  renderAction =
    a:
    {
      inherit (a) action;
    }
    // lib.optionalAttrs (a.matcher != null) { inherit (a) matcher; }
    // lib.optionalAttrs (a.command != [ ]) { inherit (a) command; };

  hooks = lib.filterAttrs (_: actions: actions != [ ]) cfg.hooks;

  hookMatcher =
    event: actions:
    let
      subject = (lib.findFirst (e: e.name == event) { subject = null; } cfg.hookEvents).subject;
      matchers = map (a: a.matcher) actions;
      unscoped = lib.any (m: m == null || m == "" || m == "*") matchers;
    in
    if subject == null || unscoped then null else lib.concatStringsSep "|" (lib.unique matchers);

  suites = lib.filterAttrs (_: s: s.enable) cfg.ruleSuites;

  suiteFile =
    n: s:
    if s.source != null then
      s.source
    else
      pkgs.writeText "${n}.yaml" (builtins.toJSON (map renderRule s.rules));

  typedRules = cfg.extraRules ++ lib.concatMap (s: s.rules) (lib.attrValues suites);

  yaml = {
    inherit (cfg)
      categories
      disabledRules
      toolInputLimits
      changeWindows
      changeWindowFiles
      prefilter
      ;
    extraRules = map renderRule cfg.extraRules;
  }
  // lib.optionalAttrs (hooks != { }) {
    hooks = lib.mapAttrs (_: map renderAction) hooks;
  };

  checkTools = lib.unique ([ "Bash" ] ++ lib.concatMap (r: r.tools) typedRules);

  stage = pkgs.linkFarm "guardrail-config" (
    [
      {
        name = "guardrail/guardrail.yaml";
        path = pkgs.writeText "guardrail.yaml" (builtins.toJSON yaml);
      }
    ]
    ++ lib.mapAttrsToList (n: s: {
      name = "guardrail/rules.d/${n}.yaml";
      path = suiteFile n s;
    }) suites
  );

  gated =
    pkgs.runCommand "guardrail-config-gated"
      {
        nativeBuildInputs = [ package ];
        passthru.gateIsThePayload = true;
      }
      ''
        XDG_CONFIG_HOME=${stage} XDG_CACHE_HOME=$TMPDIR guardrail validate --hooked-tools ${lib.concatStringsSep "," checkTools}
        cp -RL ${stage}/guardrail $out
      '';
in
{
  inherit
    yaml
    suites
    stage
    gated
    checkTools
    renderRule
    ;
  hookRegistrations = lib.mapAttrs hookMatcher hooks;
  suiteProblems = lib.mapAttrsToList (n: _: n) (
    lib.filterAttrs (_: s: (s.source != null) == (s.rules != [ ])) suites
  );
}
