{ lib, hookEvents }:
let
  inherit (lib) mkOption types;

  nullStr = description: mkOption {
    type = types.nullOr types.str;
    default = null;
    inherit description;
  };

  exampleCall = {
    input = mkOption {
      type = types.str;
      description = "The text the rule's field carries.";
    };
    tool = nullStr "Tool name of the call; default the rule's first tool, else Bash.";
    cwd = nullStr "The call's working directory.";
  };

  example = types.either types.str (types.submodule { options = exampleCall; });

  examples = {
    block = mkOption {
      type = types.listOf example;
      default = [ ];
      description = "Calls the rule must block (or warn on).";
    };
    allow = mkOption {
      type = types.listOf example;
      default = [ ];
      description = "Calls the rule must allow.";
    };
  };

  rule = {
    name = mkOption {
      type = types.str;
      description = "Rule name, shown when it fires and used by disabledRules.";
    };
    pattern = mkOption {
      type = types.str;
      description = "Regex matched against the command, or against `field` when set.";
    };
    severity = mkOption {
      type = types.enum [ "block" "warn" ];
      description = "block refuses the call; warn lets it run and says why.";
    };
    message = mkOption {
      type = types.str;
      description = "Why, shown to the agent.";
    };
    category = mkOption {
      type = types.strMatching "[a-z0-9_-]+";
      description = "Lowercase category; `categories.<name> = false` turns it off.";
    };
    window = nullStr "Change-window tag: the rule blocks unless a window with this tag is open.";
    test_block = nullStr "A call the rule must block.";
    test_allow = nullStr "A call the rule must allow.";
    examples = mkOption {
      type = types.submodule { options = examples; };
      default = { };
      description = "More block and allow cases; `guardrail validate` runs every one at rebuild.";
    };
    tools = mkOption {
      type = types.listOf types.str;
      default = [ ];
      description = "Exact tool names the rule applies to; empty means the tools `guardrail check` scans (Bash, Write, Edit, NotebookEdit, mcp__*).";
    };
    field = nullStr "The tool_input field the pattern reads; unset means the fields `guardrail check` scans for the tool.";
    cwd = nullStr "Regex the call's working directory must match for the rule to apply.";
  };

  ruleType = types.submodule { options = rule; };

  toolInputLimit = {
    name = mkOption {
      type = types.str;
      description = "Rule name shown when a call is blocked.";
    };
    tools = mkOption {
      type = types.nonEmptyListOf types.str;
      description = "Exact tool names the limit applies to; the PreToolUse hook is registered for exactly these.";
    };
    field = mkOption {
      type = types.str;
      description = "The tool input field whose length is limited.";
    };
    maxChars = mkOption {
      type = types.ints.positive;
      description = "Maximum length in characters; a longer value blocks the call.";
    };
    message = mkOption {
      type = types.str;
      description = "Why the limit exists, shown to the agent when it blocks.";
    };
  };

  utc = types.strMatching "[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z";

  changeWindow = {
    name = mkOption {
      type = types.str;
      description = "Window name shown in guardrail's messages.";
    };
    tag = mkOption {
      type = types.str;
      description = "Rules whose `window` equals this tag are allowed while the window is open.";
    };
    start = mkOption {
      type = utc;
      description = "Start, UTC, RFC 3339 with Z.";
    };
    end = mkOption {
      type = utc;
      description = "End, UTC, RFC 3339 with Z; exclusive.";
    };
  };

  strList = description: mkOption {
    type = types.listOf types.str;
    default = [ ];
    inherit description;
  };

  prefilter = {
    extraCommands = strList "Commands added to guardrail's prefilter (rules/prefilter.yaml); an unscoped rule whose command is not listed never fires.";
    removedCommands = strList "Default prefilter commands to drop.";
    extraKeywords = strList "Keywords (ASCII case-insensitive, anywhere in the command) that send a command to the rule engine.";
    extraMarkers = strList "Byte sequences that send a command to the rule engine.";
  };

  actions = [ "check" "inputLimit" "searchNudge" "searchAdvise" "mintAdvise" "genLockTie" "exec" ];

  hookAction =
    { config, ... }:
    {
      options = {
        action = mkOption {
          type = types.enum actions;
          description = "What the action does.";
        };
        matcher = nullStr "Claude Code matcher syntax: null, empty or `*` matches all, `A|B` exact names, anything else a regex.";
        command = mkOption {
          type =
            if config.action == "exec" then
              types.addCheck (types.listOf types.str) (c: c != [ ])
            else
              types.addCheck (types.listOf types.str) (c: c == [ ]);
          default = [ ];
          description = "argv for an exec action (non-empty); must be empty for every other action.";
        };
      };
    };

  suite = {
    enable = mkOption {
      type = types.bool;
      default = true;
      description = "Deploy this suite.";
    };
    source = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "The suite's YAML file (a list of guardrail rules). Exactly one of source and rules.";
    };
    rules = mkOption {
      type = types.listOf ruleType;
      default = [ ];
      description = "The suite's rules, typed; rendered to rules.d/<name>.yaml. Exactly one of source and rules.";
    };
  };

  config = {
    categories = mkOption {
      type = types.addCheck (types.attrsOf types.bool) (
        a: lib.all (n: builtins.match "[a-z0-9_-]+" n != null) (builtins.attrNames a)
      );
      default = { };
      description = "Turn a rule category off (`<category> = false`); a category not listed is on.";
    };
    extraRules = mkOption {
      type = types.listOf ruleType;
      default = [ ];
      description = "Rules rendered into guardrail.yaml, merged with the compiled-in defaults and the suites.";
    };
    disabledRules = strList "Names of rules to disable.";
    toolInputLimits = mkOption {
      type = types.listOf (types.submodule { options = toolInputLimit; });
      default = [ ];
      description = "Per-tool field length limits enforced by `guardrail input-limit`.";
    };
    changeWindows = mkOption {
      type = types.listOf (types.submodule { options = changeWindow; });
      default = [ ];
      description = "Change windows: a rule carrying a `window` tag blocks unless a window with that tag is open now.";
    };
    changeWindowFiles = strList "Files of change windows (`{changeWindows: [...]}`) written at run time, merged with changeWindows; a missing file opens nothing.";
    prefilter = prefilter;
    hooks = mkOption {
      type = types.submodule {
        options = lib.listToAttrs (
          map (
            e:
            lib.nameValuePair e.name (mkOption {
              type = types.listOf (types.submodule hookAction);
              default = [ ];
              description =
                "guardrail actions for ${e.name}, run in order by `guardrail hook ${e.name}`."
                + lib.optionalString (e.subject != null) " An action's matcher is tested against `${e.subject}`.";
            })
          ) hookEvents
        );
      };
      default = { };
      description = "Generic hooks, one option per Claude Code hook event (guardrail's hooks/events.json); an event with no actions registers nothing.";
    };
  };

  derived = {
    ruleSuites = mkOption {
      type = types.attrsOf (types.submodule { options = suite; });
      default = { };
      description = "Rule suites deployed to ~/.config/guardrail/rules.d/<name>.yaml: a YAML file or typed rules. Every suite and the rendered config pass `guardrail validate` at rebuild, or the rebuild stops.";
    };
    hookEvents = mkOption {
      type = types.listOf types.attrs;
      readOnly = true;
      default = hookEvents;
      description = "guardrail's hook event table (hooks/events.json).";
    };
    checkTools = mkOption {
      type = types.listOf types.str;
      readOnly = true;
      description = "Tools `guardrail check` must be registered for: Bash, then every tool a typed rule names.";
    };
    hookRegistrations = mkOption {
      type = types.attrsOf (types.nullOr types.str);
      readOnly = true;
      description = "Each hook event with actions, and the Claude Code matcher `guardrail hook <Event>` registers with (null matches all).";
    };
  };
in
{
  inherit
    rule
    examples
    exampleCall
    toolInputLimit
    changeWindow
    prefilter
    actions
    config
    ;
  options = config // derived;
  yamlKeys = builtins.attrNames config;
}
