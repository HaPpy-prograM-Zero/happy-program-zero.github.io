// SKILL.md checker. Runs only in the browser (or in Node for tests); nothing is uploaded.
// Each finding: {level: "error"|"warn"|"ok", rule, msg}
(function (root) {
  "use strict";

  function parseFrontmatter(text) {
    const t = text.replace(/^\uFEFF/, "").replace(/\r\n/g, "\n");
    if (!t.startsWith("---\n")) return { ok: false, reason: "start" };
    const end = t.indexOf("\n---", 4);
    if (end === -1) return { ok: false, reason: "end" };
    const raw = t.slice(4, end);
    const after = t.slice(end + 4);
    const body = after.replace(/^[^\n]*\n?/, "");
    return { ok: true, raw, body };
  }

  // Minimal YAML reader for flat "key: value" frontmatter. Reports what a strict parser would reject.
  function readKeys(raw, out) {
    const keys = {};
    const lines = raw.split("\n");
    let lastKey = null;
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const n = i + 2; // line number in the file (line 1 is ---)
      if (!line.trim() || line.trim().startsWith("#")) continue;
      if (/\t/.test(line.match(/^\s*/)[0])) {
        out.push({ level: "error", rule: "yaml-tab", msg: `Line ${n}: tab used for indentation. YAML only accepts spaces.` });
      }
      const m = line.match(/^([A-Za-z0-9_-]+):(.*)$/);
      if (!m) {
        if (/^\s+\S/.test(line) && lastKey) { keys[lastKey].cont.push(line.trim()); continue; }
        out.push({ level: "error", rule: "yaml-line", msg: `Line ${n}: not a "key: value" line. Strict YAML parsers will fail here.` });
        continue;
      }
      const key = m[1];
      const rest = m[2];
      if (rest && !rest.startsWith(" ")) {
        out.push({ level: "error", rule: "yaml-space", msg: `Line ${n}: put a space after "${key}:".` });
      }
      let v = rest.trim();
      const info = { value: v, quoted: false, block: false, cont: [], line: n };
      if (v === "|" || v === ">" || v === "|-" || v === ">-") { info.block = true; info.value = ""; }
      else if ((v.startsWith('"') && v.endsWith('"') && v.length >= 2) || (v.startsWith("'") && v.endsWith("'") && v.length >= 2)) {
        info.quoted = true; info.value = v.slice(1, -1);
      } else if (v.startsWith('"') || v.startsWith("'")) {
        out.push({ level: "error", rule: "yaml-quote", msg: `Line ${n}: "${key}" opens a quote that is not closed on the same line.` });
      } else if (/: /.test(v) || v.endsWith(":")) {
        out.push({ level: "error", rule: "yaml-colon", msg: `Line ${n}: "${key}" contains ": " without quotes. Strict YAML parsers fail here, and the skill can be dropped without any error (reported for Claude Code plugin skills and for the skills.sh installer). Wrap the value in double quotes.` });
      } else if (/ #/.test(v)) {
        out.push({ level: "warn", rule: "yaml-comment", msg: `Line ${n}: " #" inside an unquoted "${key}" starts a YAML comment; the rest of the line is dropped. Quote the value.` });
      } else if (/^[\[{&*!|>%@`]/.test(v)) {
        out.push({ level: "error", rule: "yaml-special", msg: `Line ${n}: "${key}" starts with a YAML special character (${v[0]}). Quote the value.` });
      }
      if (keys[key]) out.push({ level: "error", rule: "yaml-dup", msg: `Line ${n}: "${key}" appears twice.` });
      keys[key] = info;
      lastKey = key;
    }
    for (const k in keys) {
      if (keys[k].cont.length) keys[k].value = (keys[k].value + " " + keys[k].cont.join(" ")).trim();
    }
    return keys;
  }

  const RISKY = [
    [/curl[^\n|]*\|\s*(ba|z)?sh/i, "pipes a download straight into a shell (curl | sh)"],
    [/wget[^\n|]*\|\s*(ba|z)?sh/i, "pipes a download straight into a shell (wget | sh)"],
    [/rm\s+-[a-z]*r[a-z]*f|rm\s+-[a-z]*f[a-z]*r/i, "deletes recursively and forcibly (rm -rf)"],
    [/\bsudo\b/i, "asks for administrator rights (sudo)"],
    [/(cat|read|open|type)[^\n]{0,40}\.env\b|~\/\.ssh|id_rsa|\.aws\/credentials/i, "reads secrets (.env, SSH keys or cloud credentials)"],
    [/ignore (all |any )?(previous|prior|above) instructions/i, "contains a prompt-injection phrase"],
    [/(disable|turn off|bypass)[^\n]{0,30}(permission|sandbox|hook|safety)/i, "tells the agent to switch off a safety control"],
    [/--dangerously-skip-permissions|bypassPermissions/i, "asks to skip permission prompts"],
    [/[A-Za-z0-9+\/]{200,}={0,2}/, "contains a long encoded blob (base64?) that you cannot read"],
    [/\b(powershell|pwsh)\b[^\n]{0,40}-enc(odedcommand)?\b/i, "runs an encoded PowerShell command"],
    [/\beval\s*\(|\bexec\s*\(/i, "evaluates code built at run time (eval/exec)"],
  ];

  function lint(text, opts) {
    opts = opts || {};
    const out = [];
    if (!text || !text.trim()) return [{ level: "error", rule: "empty", msg: "The file is empty." }];
    const fm = parseFrontmatter(text);
    if (!fm.ok) {
      out.push({ level: "error", rule: "frontmatter", msg: fm.reason === "start"
        ? 'The file must start with a line containing only "---" (the frontmatter). Without it the skill is not detected.'
        : 'The frontmatter opens with "---" but never closes. Add a line with only "---" after the description.' });
      return out;
    }
    const keys = readKeys(fm.raw, out);

    // name
    const name = keys.name && keys.name.value;
    if (!name) out.push({ level: "error", rule: "name-missing", msg: 'Missing "name:". Every skill needs one.' });
    else {
      if (!/^[a-z0-9]+(-[a-z0-9]+)*$/.test(name)) out.push({ level: "error", rule: "name-format", msg: `name "${name}": use only lowercase letters, numbers and single hyphens.` });
      if (name.length > 64) out.push({ level: "error", rule: "name-length", msg: `name is ${name.length} characters; the limit is 64.` });
      if (/anthropic|claude/i.test(name)) out.push({ level: "warn", rule: "name-reserved", msg: `name contains "anthropic" or "claude". Those words are reserved in Anthropic's skill rules for uploaded skills; pick another name.` });
      if (opts.folder && opts.folder !== name) out.push({ level: "warn", rule: "name-folder", msg: `name "${name}" differs from the folder "${opts.folder}". Keep them the same so people and tools find it.` });
    }

    // description
    const d = keys.description && keys.description.value;
    if (!d) out.push({ level: "error", rule: "desc-missing", msg: 'Missing "description:". Claude decides when to use the skill from this line; without it the skill never triggers.' });
    else {
      if (d.length > 1024) out.push({ level: "error", rule: "desc-length", msg: `description is ${d.length} characters; the limit is 1024.` });
      if (d.length < 40) out.push({ level: "warn", rule: "desc-short", msg: `description is only ${d.length} characters. Say what it does AND when to use it.` });
      if (!/\bwhen(ever)?\b|\buse (it |this )?(for|before|after|if)\b|\btrigger/i.test(d)) {
        out.push({ level: "warn", rule: "desc-trigger", msg: 'description does not say WHEN to use it (e.g. "Use when the user asks to ..."). Skills without a clear trigger are often never picked.' });
      }
      if (/<[a-z][^>]*>/i.test(d)) out.push({ level: "error", rule: "desc-xml", msg: "description contains XML/HTML tags; they are not allowed there." });
      if (/^(i |i'm |we |this skill (will )?help)/i.test(d)) out.push({ level: "warn", rule: "desc-person", msg: 'Write the description in the third person ("Reviews ...", "Use when ..."), not "I/we".' });
    }

    // body
    const body = fm.body || "";
    const lines = body.split("\n").length;
    if (!body.trim()) out.push({ level: "warn", rule: "body-empty", msg: "There is no text after the frontmatter: the skill has no instructions." });
    if (lines > 500) out.push({ level: "warn", rule: "body-long", msg: `The body has ${lines} lines. Keep SKILL.md under ~500 and move detail to separate files it links to.` });
    const refs = body.match(/\]\(([^)#\s]+\.(md|py|sh|js|txt|json))\)/g) || [];
    if (refs.length && opts.listFiles) {
      for (const r of refs) {
        const p = r.slice(2, -1);
        if (!/^https?:/.test(p) && !opts.listFiles.includes(p)) out.push({ level: "warn", rule: "ref-missing", msg: `Links to "${p}", which is not in the folder.` });
      }
    }
    if (/[A-Z]:\\Users\\|\/home\/[a-z]+\/|\/Users\/[a-z]+\//.test(body)) out.push({ level: "warn", rule: "abs-path", msg: "Contains a personal absolute path (C:\\Users\\..., /home/..., /Users/...). It will not exist on other machines." });

    // safety (frontmatter + body)
    const all = text;
    for (const [re, what] of RISKY) {
      if (re.test(all)) out.push({ level: "warn", rule: "risk", msg: `Safety: it ${what}. Read that part before installing; a skill is instructions the agent will follow.` });
    }
    if (/\ballowed-tools\s*:/i.test(fm.raw) && /bash\s*\(\s*\*\s*\)|"?bash"?\s*$/im.test(fm.raw)) {
      out.push({ level: "warn", rule: "tools-wide", msg: 'allowed-tools grants Bash without limits. Prefer specific commands, e.g. Bash(git status:*).' });
    }

    if (!out.some(f => f.level === "error" || f.level === "warn")) out.push({ level: "ok", rule: "all", msg: "No problems found by these checks. Still read the whole file before installing." });
    return out;
  }

  const api = { lint, parseFrontmatter };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.SkillLint = api;
})(this);
