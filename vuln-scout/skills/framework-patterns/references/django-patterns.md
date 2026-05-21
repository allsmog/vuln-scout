---
name: django-patterns
description: Django security anti-patterns including ORM bypass SQL injection, template injection, CSRF bypass, settings exposure, mass assignment, and open redirect vulnerabilities.
---

# Django Security Patterns

## 1. ORM Bypass (SQL Injection)

**Vulnerable Pattern:** Using `raw()`, `extra()`, `RawSQL()`, or `cursor.execute()` with string formatting instead of parameterized queries.

### Detection

```bash
# Direct raw SQL methods
grep -rn "\.raw\(" --include="*.py"
grep -rn "\.extra\(" --include="*.py"
grep -rn "RawSQL\(" --include="*.py"

# Cursor-based raw SQL
grep -rn "cursor\.execute\(" --include="*.py"

# String formatting in query context
grep -rn "\.raw\(.*%" --include="*.py"
grep -rn "\.raw\(.*\.format\(" --include="*.py"
grep -rn "\.raw\(.*f\"" --include="*.py"
grep -rn "cursor\.execute\(.*%" --include="*.py"
grep -rn "cursor\.execute\(.*\.format\(" --include="*.py"
grep -rn "cursor\.execute\(.*f\"" --include="*.py"

# extra() with string interpolation
grep -rn "\.extra\(.*where.*%" --include="*.py"
```

### Vulnerable Code Patterns

```python
# raw() with string formatting - SQLI
def get_user(request):
    name = request.GET.get('name')
    users = User.objects.raw(f"SELECT * FROM auth_user WHERE username = '{name}'")
    return render(request, 'users.html', {'users': users})

# extra() with interpolation - SQLI
def search(request):
    term = request.GET.get('q')
    results = Article.objects.extra(where=["title LIKE '%%%s%%'" % term])
    return render(request, 'results.html', {'results': results})

# RawSQL annotation with user input - SQLI
from django.db.models.expressions import RawSQL
def annotated(request):
    field = request.GET.get('field')
    qs = MyModel.objects.annotate(val=RawSQL("SELECT %s FROM other_table" % field, []))
    return render(request, 'annotated.html', {'qs': qs})

# cursor.execute() with f-string - SQLI
def raw_query(request):
    user_id = request.GET.get('id')
    with connection.cursor() as cursor:
        cursor.execute(f"SELECT * FROM auth_user WHERE id = {user_id}")
        row = cursor.fetchone()
    return JsonResponse({'user': row})
```

### False Positives

```python
# Parameterized raw() - SAFE
User.objects.raw("SELECT * FROM auth_user WHERE id = %s", [user_id])

# Parameterized cursor.execute() - SAFE
cursor.execute("SELECT * FROM auth_user WHERE id = %s", [user_id])

# ORM queryset methods - SAFE
User.objects.filter(username=name)
User.objects.get(pk=user_id)
```

### Remediation

```python
# Always use parameterized queries
def get_user(request):
    name = request.GET.get('name')
    users = User.objects.raw("SELECT * FROM auth_user WHERE username = %s", [name])
    return render(request, 'users.html', {'users': users})

# Prefer ORM methods over raw SQL
User.objects.filter(username=name)
```

---

## 2. Template Injection (SSTI)

**Vulnerable Pattern:** Constructing Django templates from user-controlled input via `Template()` and rendering with `Context()`.

### Detection

```bash
# Direct template construction from strings
grep -rn "Template(" --include="*.py" | grep -v "get_template\|loader\|import"
grep -rn "from django.template import.*Template" --include="*.py"

# Template + Context rendering
grep -rn "\.render(Context\(" --include="*.py"
grep -rn "\.render(RequestContext\(" --include="*.py"

# String formatting before template construction
grep -rn "Template(.*%" --include="*.py"
grep -rn "Template(.*\.format\(" --include="*.py"
grep -rn "Template(.*f\"" --include="*.py"
```

### Vulnerable Code Patterns

```python
from django.template import Template, Context

# User input directly in template string - SSTI
def greet(request):
    name = request.GET.get('name')
    template = Template(f"Hello, {name}!")
    return HttpResponse(template.render(Context({})))

# Template constructed from database with user-controlled content
def render_page(request, page_id):
    page = Page.objects.get(id=page_id)
    template = Template(page.content)  # If content is user-editable
    return HttpResponse(template.render(Context({'request': request})))
```

### False Positives

```python
# Loading from filesystem - SAFE
from django.template.loader import get_template
template = get_template('greet.html')

# render_to_string with file template - SAFE
from django.template.loader import render_to_string
html = render_to_string('email.html', {'name': name})

# render() shortcut with file template - SAFE
return render(request, 'greet.html', {'name': name})
```

### Remediation

```python
# Always load templates from files, pass user input as context
def greet(request):
    name = request.GET.get('name')
    return render(request, 'greet.html', {'name': name})
```

---

## 3. CSRF Bypass

**Vulnerable Pattern:** Using `@csrf_exempt` on state-changing views, disabling CSRF middleware entirely, or misconfiguring trusted origins.

### Detection

```bash
# Views exempt from CSRF
grep -rn "@csrf_exempt" --include="*.py"
grep -rn "csrf_exempt" --include="*.py"

# Middleware removal
grep -rn "CsrfViewMiddleware" --include="*.py" | grep -v "^#"

# Trusted origins misconfiguration
grep -rn "CSRF_TRUSTED_ORIGINS" --include="*.py"
grep -rn "CSRF_COOKIE_SECURE\s*=\s*False" --include="*.py"
```

### Vulnerable Code Patterns

```python
# csrf_exempt on state-changing view - CSRF BYPASS
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt
def transfer_funds(request):
    if request.method == 'POST':
        to_account = request.POST.get('to')
        amount = request.POST.get('amount')
        perform_transfer(request.user, to_account, amount)
        return JsonResponse({'status': 'ok'})

# CSRF middleware removed entirely - ALL views unprotected
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    # 'django.middleware.csrf.CsrfViewMiddleware',  # REMOVED!
    'django.contrib.auth.middleware.AuthenticationMiddleware',
]

# Overly permissive trusted origins
CSRF_TRUSTED_ORIGINS = ['https://*.example.com', 'http://*']
```

### False Positives

- `@csrf_exempt` on webhook endpoints that verify signatures (e.g., Stripe webhooks)
- `@csrf_exempt` on API views protected by token authentication (DRF `TokenAuthentication`)
- Views decorated with both `@csrf_exempt` and `@require_GET` (read-only)

### Remediation

```python
# For API endpoints, use DRF with proper authentication instead of csrf_exempt
from rest_framework.decorators import api_view, authentication_classes
from rest_framework.authentication import TokenAuthentication

@api_view(['POST'])
@authentication_classes([TokenAuthentication])
def transfer_funds(request):
    # Token auth replaces CSRF protection for APIs
    pass
```

---

## 4. Settings Exposure

**Vulnerable Pattern:** Insecure Django settings that expose sensitive information or weaken security posture.

### Detection

```bash
# Debug mode enabled
grep -rn "DEBUG\s*=\s*True" --include="*.py" --include="*.env"

# Hardcoded secret key
grep -rn "SECRET_KEY\s*=" --include="*.py" | grep -v "os\.environ\|config\|getenv"

# Wildcard allowed hosts
grep -rn "ALLOWED_HOSTS" --include="*.py" | grep "\*"

# Insecure cookie settings
grep -rn "SESSION_COOKIE_SECURE\s*=\s*False" --include="*.py"
grep -rn "SESSION_COOKIE_HTTPONLY\s*=\s*False" --include="*.py"
grep -rn "CSRF_COOKIE_SECURE\s*=\s*False" --include="*.py"

# Security middleware absent
grep -rn "SECURE_SSL_REDIRECT\s*=\s*False" --include="*.py"
grep -rn "SECURE_HSTS_SECONDS\s*=\s*0" --include="*.py"
```

### Vulnerable Code Patterns

```python
# settings.py - multiple misconfigurations

DEBUG = True  # Exposes tracebacks, SQL queries, and settings in production

SECRET_KEY = 'django-insecure-abc123def456'  # Hardcoded, predictable

ALLOWED_HOSTS = ['*']  # Accepts any Host header, enables Host header injection

SESSION_COOKIE_SECURE = False  # Cookie sent over HTTP
SESSION_COOKIE_HTTPONLY = False  # Cookie accessible via JavaScript
CSRF_COOKIE_SECURE = False  # CSRF cookie sent over HTTP
SECURE_SSL_REDIRECT = False  # No HTTPS enforcement
```

### Exploitation

- `DEBUG=True`: Visit any URL that triggers a 500 error to see full traceback including settings, installed apps, middleware, and local variables
- Hardcoded `SECRET_KEY`: Forge session cookies, CSRF tokens, and password reset tokens
- `ALLOWED_HOSTS = ['*']`: Host header injection for cache poisoning, password reset poisoning

### Remediation

```python
import os

DEBUG = os.environ.get('DJANGO_DEBUG', 'False') == 'True'
SECRET_KEY = os.environ['DJANGO_SECRET_KEY']
ALLOWED_HOSTS = os.environ.get('DJANGO_ALLOWED_HOSTS', '').split(',')

SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_SECURE = True
SECURE_SSL_REDIRECT = True
SECURE_HSTS_SECONDS = 31536000
```

---

## 5. Mass Assignment

**Vulnerable Pattern:** `ModelForm` with `fields = '__all__'` or using `exclude` instead of explicit `fields`, allowing attackers to set unintended model fields.

### Detection

```bash
# ModelForm with all fields
grep -rn "fields\s*=\s*'__all__'" --include="*.py"
grep -rn 'fields\s*=\s*"__all__"' --include="*.py"

# ModelForm using exclude (risk of forgetting sensitive fields)
grep -rn "exclude\s*=" --include="*.py" | grep -i "class.*Meta\|form"

# CreateView / UpdateView without form_class restriction
grep -rn "class.*CreateView\|class.*UpdateView" --include="*.py" -A 5 | grep "fields\s*=\s*'__all__'"

# Direct model creation from request data
grep -rn "\.objects\.create\(\*\*request\." --include="*.py"
grep -rn "\.objects\.create\(\*\*request\.POST" --include="*.py"
```

### Vulnerable Code Patterns

```python
# ModelForm with all fields exposes is_staff, is_superuser
class UserForm(forms.ModelForm):
    class Meta:
        model = User
        fields = '__all__'  # Includes is_staff, is_superuser, password!

# exclude misses new fields added later
class ProfileForm(forms.ModelForm):
    class Meta:
        model = Profile
        exclude = ['user']  # What if 'role' or 'is_admin' is added later?

# Direct creation from POST data
def register(request):
    User.objects.create(**request.POST.dict())  # Attacker controls all fields!
```

### False Positives

- Admin-only forms where the view is protected by `@staff_member_required` or `IsAdminUser`
- Forms with custom `__init__` that dynamically restricts fields
- Serializers with explicit `read_only_fields` covering sensitive attributes

### Remediation

```python
# Explicit field whitelist
class UserRegistrationForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['username', 'email', 'password']  # Explicit whitelist

# For DRF serializers
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'email']
        read_only_fields = ['is_staff', 'is_superuser']
```

---

## 6. Open Redirect

**Vulnerable Pattern:** Redirecting to a URL taken directly from user input without validation.

### Detection

```bash
# Redirect with user-controlled URL
grep -rn "HttpResponseRedirect\(request\." --include="*.py"
grep -rn "redirect\(request\." --include="*.py"
grep -rn "HttpResponseRedirect\(.*GET\[" --include="*.py"
grep -rn "redirect\(.*GET\[" --include="*.py"

# Common parameter names for redirects
grep -rn "request\.GET\.get\(['\"]next\|request\.GET\.get\(['\"]redirect\|request\.GET\.get\(['\"]url\|request\.GET\.get\(['\"]return" --include="*.py"
```

### Vulnerable Code Patterns

```python
# Direct redirect from query parameter - OPEN REDIRECT
def login_view(request):
    if request.method == 'POST':
        user = authenticate(request, **request.POST)
        if user:
            login(request, user)
            next_url = request.GET.get('next', '/')
            return HttpResponseRedirect(next_url)  # Attacker: ?next=https://evil.com

# redirect() shortcut with user input
def logout_view(request):
    logout(request)
    return redirect(request.GET.get('redirect', '/'))  # Open redirect
```

### Exploitation

```
https://example.com/login?next=https://evil.com/phishing
https://example.com/login?next=//evil.com  (protocol-relative)
https://example.com/login?next=/\evil.com  (backslash bypass)
```

### False Positives

- `redirect()` with hardcoded paths: `redirect('/dashboard')`
- Use of `url_has_allowed_host_and_scheme()` before redirect
- Django's built-in `LoginView` with `REDIRECT_FIELD_NAME` validated against `LOGIN_REDIRECT_URL`

### Remediation

```python
from django.utils.http import url_has_allowed_host_and_scheme

def login_view(request):
    if request.method == 'POST':
        user = authenticate(request, **request.POST)
        if user:
            login(request, user)
            next_url = request.GET.get('next', '/')
            if not url_has_allowed_host_and_scheme(
                next_url,
                allowed_hosts={request.get_host()},
                require_https=request.is_secure(),
            ):
                next_url = '/'
            return HttpResponseRedirect(next_url)
```

---

## 7. Clickjacking (Missing X-Frame-Options)

**Vulnerable Pattern:** Removing `XFrameOptionsMiddleware` or using `@xframe_options_exempt` on sensitive views.

### Detection

```bash
# Middleware removal
grep -rn "XFrameOptionsMiddleware" --include="*.py"

# Exempt decorator
grep -rn "@xframe_options_exempt" --include="*.py"

# X_FRAME_OPTIONS setting
grep -rn "X_FRAME_OPTIONS" --include="*.py"
```

---

## Remediation Patterns

### Secure Settings Template

```python
# settings/production.py
import os

DEBUG = False
SECRET_KEY = os.environ['DJANGO_SECRET_KEY']
ALLOWED_HOSTS = os.environ['DJANGO_ALLOWED_HOSTS'].split(',')

CSRF_COOKIE_SECURE = True
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SECURE_SSL_REDIRECT = True
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'
```

### Security Checklist Commands

```bash
# Django's built-in security checker
python manage.py check --deploy

# Comprehensive grep sweep
grep -rniE "(\.raw\(|\.extra\(|RawSQL\(|cursor\.execute|csrf_exempt|DEBUG\s*=\s*True|SECRET_KEY\s*=\s*['\"]|fields\s*=\s*'__all__'|ALLOWED_HOSTS.*\*)" --include="*.py"
```

---

## Integration with Chain Detection

Django vulnerabilities often chain with:
- Reverse proxy misconfiguration allowing Host header injection
- Internal APIs accessed via SSRF from frontend frameworks
- Session fixation via insecure cookie settings
- Privilege escalation via mass assignment on User model

When Django ORM bypass is found:
1. Trace the data flow from request parameter to `raw()`/`extra()` call
2. Check if any ORM method accepts user-controlled field names (e.g., `order_by(request.GET['sort'])`)
3. Verify whether Django's SQL compiler properly parameterizes `extra()` conditions
4. Look for second-order injection via model fields stored and later used in raw queries

## CWE References

| Vulnerability | CWE | Name |
|---------------|-----|------|
| ORM Bypass (SQLi) | CWE-89 | SQL Injection |
| Template Injection | CWE-1336 | Template Engine Injection |
| CSRF Bypass | CWE-352 | Cross-Site Request Forgery |
| Debug Mode Exposure | CWE-215 | Insertion of Sensitive Information Into Debugging Code |
| Mass Assignment | CWE-915 | Improperly Controlled Modification of Dynamically-Determined Object Attributes |
| Open Redirect | CWE-601 | URL Redirection to Untrusted Site |
