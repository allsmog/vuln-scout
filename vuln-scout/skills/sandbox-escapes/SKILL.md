---
name: Sandbox Escapes
description: This skill should be used when the user asks about "sandbox escape", "vm escape", "template injection to RCE", "SSTI exploitation", "vm2 bypass", "restricted execution bypass", "sandbox breakout", or needs to identify sandbox escape and template engine exploitation techniques during whitebox pentesting.
version: 1.0.0
---

# Sandbox Escape Techniques

Techniques for escaping restricted execution environments and exploiting template engines across Node.js, Python, and Ruby.

## When to Use

Activate this skill during:
- Code review where `vm`, `eval`, or template engines process user input
- Identifying SSTI-to-RCE exploitation paths
- Analyzing restricted execution environments (vm2, RestrictedPython, $SAFE)
- Building exploit chains that leverage sandbox escapes

## Language-Specific References

- **Node.js**: `nodejs-sandbox-escape.md` -- vm module bypass, vm2 CVEs, EJS/Pug injection, prototype pollution to RCE
- **Python**: `python-sandbox-escape.md` -- Jinja2 SSTI, Mako exploitation, serialization attacks, RestrictedPython bypass
- **Ruby**: `ruby-sandbox-escape.md` -- ERB injection, Slim/Haml exploitation, $SAFE bypasses, Marshal deserialization
