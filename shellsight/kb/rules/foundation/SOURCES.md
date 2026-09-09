# Bundled disk rule pack — sources & attribution

| File | Source | License | Notes |
|---|---|---|---|
| signature-base-thor-webshells.yar | https://github.com/Neo23x0/signature-base (yara/thor-webshells.yar) | DRL-1.1 | 624 webshell rules; attribution-on-match required (each rule's `author` meta is surfaced in ShellSight findings) |
| php-malware-finder.yar | https://github.com/nbs-system/php-malware-finder | LGPL-3.0 | Ported to YARA-X; PHP-only rules (DodgyPhp/ObfuscatedPhp/DangerousPhp/PasswordProtection) gated with `IsPhp` so they don't fire on JSP/ASPX; FP-prone strings neutered |
| nsa-webshells-core.yar | https://github.com/nsacyber/Mitigating-Web-Shells (core.webshell_detection.yara) | CC0-1.0 | Public domain; low-FP "core" set (PHP shells + generic_jsp + reGeorg ASPX + inert SolarWinds PE IOCs). EXTENDED pack intentionally NOT bundled — it duplicates php-malware-finder (DodgyPhp/ObfuscatedPhp) and is more FP-prone |

Licenses: DRL-1.1 permits use/modify/distribute/sell with attribution; LGPL-3.0 (rules ship as data); CC0-1.0 is public domain.
Regenerate the THOR pack: `cmd/diskprobe/scripts/curate-rules.sh`
