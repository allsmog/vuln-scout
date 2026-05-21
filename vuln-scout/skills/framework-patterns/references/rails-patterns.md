---
name: rails-patterns
description: Ruby on Rails security anti-patterns including mass assignment, SQL injection, SSTI, command injection, insecure deserialization, unscoped finds, and arbitrary file rendering.
---

# Ruby on Rails Security Patterns

## 1. Mass Assignment

**Vulnerable Pattern:** Using `permit!` to allow all parameters, or permitting sensitive attributes like `admin`, `role`, or `user_id` through strong parameters.

### Detection

```bash
# permit! allows everything
grep -rn "permit!" --include="*.rb"

# Check for overpermission of sensitive attributes
grep -rn "\.permit\(" --include="*.rb" | grep -iE "admin|role|owner|user_id|is_admin|superuser|level|privilege"

# Direct mass assignment without strong params
grep -rn "\.new\(params\[" --include="*.rb"
grep -rn "\.create\(params\[" --include="*.rb"
grep -rn "\.update\(params\[" --include="*.rb"
grep -rn "\.assign_attributes\(params" --include="*.rb"

# Check if attr_accessible or attr_protected are used (Rails 3 legacy)
grep -rn "attr_accessible\|attr_protected" --include="*.rb"
```

### Vulnerable Code Patterns

```ruby
# permit! allows all parameters - MASS ASSIGNMENT
class UsersController < ApplicationController
  def create
    @user = User.new(params.require(:user).permit!)
    @user.save
  end
end

# Permitting sensitive attributes
class UsersController < ApplicationController
  def update
    @user = User.find(params[:id])
    @user.update(params.require(:user).permit(:name, :email, :admin))  # :admin!
  end
end

# Direct params without strong parameters
class PostsController < ApplicationController
  def create
    @post = Post.create(params[:post])  # No filtering at all
  end
end
```

### False Positives

- `permit!` in admin controllers protected by authorization (e.g., Pundit, CanCanCan)
- `permit!` in seed files or Rake tasks (not user-facing)
- Strong parameters that permit `:role` but are guarded by `authorize!` checks

### Remediation

```ruby
class UsersController < ApplicationController
  def create
    @user = User.new(user_params)
    @user.save
  end

  private

  def user_params
    params.require(:user).permit(:name, :email, :password, :password_confirmation)
    # Never permit :admin, :role, :is_superuser
  end
end
```

---

## 2. SQL Injection

**Vulnerable Pattern:** String interpolation or concatenation in ActiveRecord `where`, `find_by_sql`, `order`, `pluck`, `group`, `having`, `joins`, or `select` methods.

### Detection

```bash
# String interpolation in where clauses
grep -rn '\.where("' --include="*.rb" | grep '#{'
grep -rn "\.where('" --include="*.rb" | grep '#{'

# find_by_sql with interpolation
grep -rn "find_by_sql" --include="*.rb"

# order/group/select with user input
grep -rn "\.order(" --include="*.rb" | grep -E "params|#\{"
grep -rn "\.group(" --include="*.rb" | grep -E "params|#\{"
grep -rn "\.select(" --include="*.rb" | grep -E "params|#\{"
grep -rn "\.pluck(" --include="*.rb" | grep -E "params|#\{"

# joins with string interpolation
grep -rn "\.joins(" --include="*.rb" | grep '#{'

# having clause injection
grep -rn "\.having(" --include="*.rb" | grep -E "params|#\{"

# raw execute with interpolation
grep -rn "\.execute(" --include="*.rb" | grep '#{'
grep -rn "exec_query(" --include="*.rb" | grep '#{'
```

### Vulnerable Code Patterns

```ruby
# String interpolation in where - SQLI
def search
  name = params[:name]
  @users = User.where("name = '#{name}'")
end

# find_by_sql with interpolation - SQLI
def lookup
  @user = User.find_by_sql("SELECT * FROM users WHERE id = #{params[:id]}")
end

# order with user input - SQLI
def index
  @users = User.order("#{params[:sort]} #{params[:direction]}")
end

# Concatenation in condition - SQLI
def filter
  conditions = "status = '" + params[:status] + "'"
  @records = Record.where(conditions)
end
```

### False Positives

```ruby
# Hash conditions - SAFE
User.where(name: params[:name])

# Array conditions with placeholders - SAFE
User.where("name = ?", params[:name])
User.where("name = :name", name: params[:name])

# Arel predicates - SAFE
User.where(User.arel_table[:name].eq(params[:name]))

# sanitize_sql_array - SAFE
User.where(ActiveRecord::Base.sanitize_sql_array(["name = ?", params[:name]]))
```

### Remediation

```ruby
# Use hash conditions
User.where(name: params[:name])

# Use placeholder syntax
User.where("name = ? AND active = ?", params[:name], true)

# For order, whitelist allowed columns
ALLOWED_SORT_COLUMNS = %w[name email created_at].freeze
ALLOWED_DIRECTIONS = %w[asc desc].freeze

def index
  sort = ALLOWED_SORT_COLUMNS.include?(params[:sort]) ? params[:sort] : 'created_at'
  dir = ALLOWED_DIRECTIONS.include?(params[:direction]) ? params[:direction] : 'asc'
  @users = User.order("#{sort} #{dir}")
end
```

---

## 3. Server-Side Template Injection (SSTI)

**Vulnerable Pattern:** Using `ERB.new()` with user-controlled input to construct and evaluate templates at runtime.

### Detection

```bash
# ERB template construction from strings
grep -rn "ERB\.new(" --include="*.rb"

# Slim/Haml template construction from strings
grep -rn "Slim::Template\.new\|Haml::Engine\.new" --include="*.rb"

# Erubi/Erubis template construction
grep -rn "Erubi::Engine\.new\|Erubis::Eruby\.new" --include="*.rb"

# render inline with user input
grep -rn "render\s*inline:" --include="*.rb"
```

### Vulnerable Code Patterns

```ruby
# ERB with user input - SSTI
def preview
  template = ERB.new(params[:template])
  result = template.result(binding)  # Full access to current scope!
  render html: result.html_safe
end

# render inline with user input - SSTI
def greet
  render inline: "Hello, <%= params[:name] %>"
end

# Haml with user input - SSTI
def preview_haml
  engine = Haml::Engine.new(params[:content])
  render html: engine.render.html_safe
end
```

### False Positives

- `ERB.new` with hardcoded template strings or file contents not controlled by users
- `render inline:` with static strings containing no user input
- Template rendering in mailer views (loaded from filesystem)

### Remediation

```ruby
# Never pass user input to ERB.new or render inline
# Always use template files with escaped variables
def greet
  @name = params[:name]
  render 'greet'  # Uses app/views/greet.html.erb with auto-escaping
end
```

---

## 4. Command Injection

**Vulnerable Pattern:** Passing user input to shell execution functions without sanitization.

### Detection

```bash
# System calls with potential user input
grep -rn "system(" --include="*.rb"

# Backtick execution
grep -rn '`.*#\{' --include="*.rb"

# %x with interpolation
grep -rn '%x(' --include="*.rb"
grep -rn '%x\[' --include="*.rb"

# IO.popen
grep -rn "IO\.popen(" --include="*.rb"

# Open3 methods
grep -rn "Open3\." --include="*.rb"

# Kernel.spawn
grep -rn "spawn(" --include="*.rb"

# open() with pipe (Kernel#open)
grep -rn "open(" --include="*.rb" | grep '|'
```

### Vulnerable Code Patterns

```ruby
# system() with string interpolation - COMMAND INJECTION
def ping
  host = params[:host]
  system("ping -c 3 #{host}")  # host="; cat /etc/passwd"
end

# Backticks with interpolation - COMMAND INJECTION
def disk_usage
  path = params[:path]
  output = `du -sh #{path}`  # path="; rm -rf /"
  render plain: output
end

# IO.popen with string - COMMAND INJECTION
def convert
  filename = params[:file]
  IO.popen("convert #{filename} output.png")
end

# open() with pipe prefix - COMMAND INJECTION
def read_url
  data = open("|curl #{params[:url]}")  # Kernel#open interprets | as pipe
  render plain: data.read
end
```

### False Positives

```ruby
# Array form of system() - SAFE (no shell interpretation)
system("ping", "-c", "3", params[:host])

# Open3 with array args - SAFE
Open3.capture3("convert", params[:file], "output.png")

# Shellwords.shellescape - SAFE (if applied correctly)
require 'shellwords'
system("ping -c 3 #{Shellwords.shellescape(params[:host])}")
```

### Remediation

```ruby
# Use array form to avoid shell interpretation
system("ping", "-c", "3", params[:host])

# Use Open3 with separate arguments
require 'open3'
stdout, stderr, status = Open3.capture3("convert", input_file, "output.png")

# If shell is required, use Shellwords
require 'shellwords'
system("ping -c 3 #{Shellwords.shellescape(host)}")
```

---

## 5. Insecure Deserialization

**Vulnerable Pattern:** Using `Marshal.load`, `YAML.load` (pre-Psych 4), or `JSON.parse` with custom create additions on untrusted data.

### Detection

```bash
# Marshal deserialization
grep -rn "Marshal\.load\|Marshal\.restore" --include="*.rb"

# YAML deserialization (unsafe before Psych 4 / Ruby 3.1)
grep -rn "YAML\.load(" --include="*.rb"
grep -rn "YAML\.unsafe_load" --include="*.rb"

# JSON with create_additions
grep -rn "JSON\.parse.*create_additions" --include="*.rb"

# Oj with :object mode
grep -rn "Oj\.load\|Oj\.object_load" --include="*.rb"

# Cookie/session deserialization
grep -rn "cookies\.signed\|cookies\.encrypted" --include="*.rb"
grep -rn "Marshal" --include="*.rb" | grep -i "cookie\|session"
```

### Vulnerable Code Patterns

```ruby
# Marshal.load on user input - RCE
def import_data
  data = Base64.decode64(params[:data])
  objects = Marshal.load(data)  # Arbitrary code execution!
  render json: objects
end

# YAML.load on user input (Ruby < 3.1) - RCE
def parse_config
  config = YAML.load(params[:yaml_content])  # Deserialization gadget chains!
  render json: config
end

# YAML.unsafe_load (any Ruby version) - RCE
def parse_document
  doc = YAML.unsafe_load(uploaded_file.read)
  render json: doc
end
```

### False Positives

```ruby
# YAML.safe_load - SAFE
config = YAML.safe_load(params[:yaml_content])

# YAML.load in Ruby 3.1+ defaults to safe_load behavior - SAFE (but explicit is better)
# Marshal.load on trusted internal data (cache, session store) - generally SAFE
Rails.cache.read("key")  # Uses Marshal internally but on trusted data
```

### Remediation

```ruby
# Use YAML.safe_load with permitted classes
config = YAML.safe_load(
  params[:yaml_content],
  permitted_classes: [Date, Time],
  permitted_symbols: [],
  aliases: false
)

# Use JSON instead of Marshal for data exchange
data = JSON.parse(params[:data])

# If Marshal is required, verify with HMAC first
def safe_unmarshal(signed_data, secret)
  data, signature = signed_data.split('--')
  expected = OpenSSL::HMAC.hexdigest('SHA256', secret, data)
  raise "Tampered!" unless ActiveSupport::SecurityUtils.secure_compare(signature, expected)
  Marshal.load(Base64.decode64(data))
end
```

---

## 6. Unscoped Find

**Vulnerable Pattern:** Using `Model.find(params[:id])` without scoping to the current user, allowing Insecure Direct Object Reference (IDOR).

### Detection

```bash
# Direct model find without scoping
grep -rn "\.find(params\[" --include="*.rb"
grep -rn "\.find_by(id: params\[" --include="*.rb"
grep -rn "\.find_by_id(params\[" --include="*.rb"

# Check if scoped to current_user
grep -rn "\.find(params\[" --include="*.rb" | grep -v "current_user"
```

### Vulnerable Code Patterns

```ruby
# Unscoped find - IDOR
class InvoicesController < ApplicationController
  def show
    @invoice = Invoice.find(params[:id])  # Any user can view any invoice!
  end

  def destroy
    @invoice = Invoice.find(params[:id])  # Any user can delete any invoice!
    @invoice.destroy
  end
end

# Unscoped update
class ProfilesController < ApplicationController
  def update
    @profile = Profile.find(params[:id])  # Can update other users' profiles!
    @profile.update(profile_params)
  end
end
```

### False Positives

- Finds within scoped associations: `current_user.invoices.find(params[:id])`
- Controllers protected by Pundit: `authorize @invoice`
- Public resources that should be viewable by anyone (blog posts, product pages)

### Remediation

```ruby
class InvoicesController < ApplicationController
  def show
    @invoice = current_user.invoices.find(params[:id])  # Scoped to current user
  end

  # Or use authorization library
  def show
    @invoice = Invoice.find(params[:id])
    authorize @invoice  # Pundit policy check
  end
end
```

---

## 7. Render Arbitrary File

**Vulnerable Pattern:** Using `render file:` with user-controlled path, enabling local file disclosure.

### Detection

```bash
# render file with user input
grep -rn "render\s*file:" --include="*.rb"
grep -rn "render\s*:file" --include="*.rb"

# send_file with user input
grep -rn "send_file(" --include="*.rb" | grep -E "params|#\{"

# send_data with file read
grep -rn "send_data.*File\.read\|send_data.*IO\.read" --include="*.rb"

# File.read with user input
grep -rn "File\.read(.*params" --include="*.rb"
grep -rn "File\.open(.*params" --include="*.rb"
```

### Vulnerable Code Patterns

```ruby
# render file with user-controlled path - LFI
def show_file
  render file: params[:path]  # path=/etc/passwd
end

# send_file with user input - LFI
def download
  send_file params[:file]  # file=../../config/credentials.yml.enc
end

# File.read with path traversal
def view_log
  content = File.read("logs/#{params[:name]}")  # name=../../etc/passwd
  render plain: content
end
```

### Remediation

```ruby
# Whitelist allowed files
ALLOWED_FILES = %w[terms privacy faq].freeze

def show_file
  unless ALLOWED_FILES.include?(params[:page])
    raise ActionController::RoutingError, 'Not Found'
  end
  render file: Rails.root.join('public', "#{params[:page]}.html")
end

# Use send_file with path validation
def download
  filename = File.basename(params[:file])  # Strip directory traversal
  path = Rails.root.join('uploads', filename)
  unless File.exist?(path) && path.to_s.start_with?(Rails.root.join('uploads').to_s)
    raise ActiveRecord::RecordNotFound
  end
  send_file path
end
```

---

## 8. Cross-Site Scripting (XSS)

**Vulnerable Pattern:** Using `raw`, `html_safe`, or `<%== %>` to render user-controlled content without escaping.

### Detection

```bash
# html_safe on user-controlled data
grep -rn "\.html_safe" --include="*.rb" --include="*.erb"

# raw helper in templates
grep -rn "<%= raw" --include="*.erb"

# Unescaped output tag
grep -rn "<%==" --include="*.erb"

# sanitize with permissive tags
grep -rn "sanitize(" --include="*.rb" --include="*.erb" | grep -i "tags\|attributes"
```

### False Positives

- `html_safe` on hardcoded strings or trusted internal content
- `raw` rendering output from a sanitization library (e.g., `Sanitize.fragment`)
- Content from a trusted CMS with server-side sanitization

### Remediation

```ruby
# Use Rails auto-escaping (default in ERB)
<%= user.name %>  # Auto-escaped

# If HTML is needed, sanitize first
<%= sanitize(user.bio, tags: %w[b i em strong], attributes: %w[]) %>
```

---

## Remediation Patterns

### Security Headers

```ruby
# config/application.rb or initializer
config.action_dispatch.default_headers = {
  'X-Frame-Options' => 'DENY',
  'X-Content-Type-Options' => 'nosniff',
  'X-XSS-Protection' => '0',
  'Referrer-Policy' => 'strict-origin-when-cross-origin',
  'Content-Security-Policy' => "default-src 'self'"
}
```

### Security Audit Commands

```bash
# Brakeman static analysis
brakeman -A -q --no-pager

# bundler-audit for dependency vulnerabilities
bundle audit check --update

# Comprehensive grep sweep
grep -rniE "(permit!|\.where\(\".*#\{|find_by_sql|Marshal\.load|YAML\.load\(|ERB\.new\(|render\s+file:|render\s+inline:|\.html_safe|<%==)" --include="*.rb" --include="*.erb"
```

---

## Integration with Chain Detection

Rails vulnerabilities often chain with:
- Mass assignment escalating to admin via `is_admin` parameter
- SQL injection in search combined with unscoped find for data exfiltration
- Insecure deserialization via cookie tampering when secret_key_base is leaked
- Command injection via image processing (ImageMagick/MiniMagick) with uploaded files

When a Rails vulnerability is found:
1. Check `config/routes.rb` for exposed endpoints and RESTful resource definitions
2. Verify `Gemfile.lock` for known vulnerable gem versions
3. Inspect `config/initializers/` for security-relevant configuration
4. Review `app/policies/` or `app/models/ability.rb` for authorization gaps
5. Check `config/credentials.yml.enc` and `config/master.key` handling

## CWE References

| Vulnerability | CWE | Name |
|---------------|-----|------|
| Mass Assignment | CWE-915 | Improperly Controlled Modification of Dynamically-Determined Object Attributes |
| SQL Injection | CWE-89 | SQL Injection |
| SSTI | CWE-1336 | Template Engine Injection |
| Command Injection | CWE-78 | OS Command Injection |
| Insecure Deserialization | CWE-502 | Deserialization of Untrusted Data |
| IDOR (Unscoped Find) | CWE-639 | Authorization Bypass Through User-Controlled Key |
| Arbitrary File Render | CWE-22 | Path Traversal |
| XSS | CWE-79 | Cross-site Scripting |
