// ShellSight own rules — gap-filling heuristics not covered by YARA Forge.
// These ship with the binary and are updated per ShellSight release.
// Coverage: PHP eval/obfuscated, JSP exec/reflection, ASPX eval/Process.Start/Reflection,
//           Ice Scorpion encrypted payload, Behinder ASPX, China Chopper ASPX, classic ASP.

rule php_eval_request_webshell {
    meta:
        description = "PHP eval/assert on user-controlled input (classic webshell)"
        author      = "ShellSight"
        license     = "MIT"
        family      = "GenericEval"
        score       = "70"
        shellsight_lang = "php"
        shellsight_cells = "php/dispatch/eval-request"
    strings:
        // ShellSight: require ADJACENCY (eval/assert applied to input/decoder), not
        // "eval anywhere + $_POST anywhere" — the latter FP'd on phpMyAdmin files that
        // use assert() as a plain code assertion while also reading request input.
        // eval/assert applied directly to (optionally base64-wrapped) request input
        $eval_req = /\b(eval|assert)\s*\(\s*@?\s*(base64_decode\s*\(\s*@?\s*)?\$_(GET|POST|REQUEST|COOKIE|SERVER)/ nocase
        // eval/assert wrapping a payload-decoder chain (packed shell). Allow a bounded
        // INTRA-statement gap (no ;{}) so wrappers like eval("?>".gzinflate(base64_decode(..)))
        // and eval(stripslashes(base64_decode(..))) still match, without going file-wide.
        $eval_dec = /\b(eval|assert)\s*\(\s*@?\s*[^;{}]{0,60}(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|convert_uudecode|hex2bin|rawurldecode)\s*\(/ nocase
        // eval (not assert — assertions are common in benign code) of a bare variable
        $eval_var = /\beval\s*\(\s*@?\s*\$[a-zA-Z_]\w*\s*\)/ nocase
    condition:
        filesize < 300KB and any of ($eval_req, $eval_dec, $eval_var)
}

rule php_antsword_payload {
    meta:
        description = "AntSword (Zhongguo Chopper) PHP payload wrapper — asenc/asoutput output framing, ERROR:// catch prefix, open_basedir bypass token"
        author      = "ShellSight"
        license     = "MIT"
        family      = "AntSword"
        score       = "90"
        shellsight_lang = "php"
        shellsight_cells = "php/family/antsword"
        reference   = "https://github.com/AntSwordProject/antSword"
    strings:
        // AntSword's complete() always wraps the payload in this ob_start/asoutput/asenc framing,
        // regardless of encoder — so it survives into the chr/chr16/rot13-decoded layer too. The
        // deobfuscate engine folds chr(N)/chr(0xNN) runs to cleartext, exposing this wrapper.
        $asoutput = "function asoutput()" nocase
        $asenc    = "asenc(" nocase
        $errpfx   = "ERROR://"
        $obget    = "ob_get_contents()" nocase
        // base64("/;|:/") — the exact split token in AntSword's open_basedir bypass loop.
        $obbypass = "Lzt8Oi8="
    condition:
        filesize < 2MB and (
            ($asoutput and $asenc) or
            ($asenc and $errpfx and $obget) or
            $obbypass
        )
}

rule jsp_command_exec_webshell {
    meta:
        description = "JSP/JSPX command execution: Runtime.getRuntime()/ProcessBuilder in a page that reads web-request input"
        author      = "ShellSight"
        license     = "MIT"
        family      = "GenericJSP"
        score       = "75"
        shellsight_lang = "jsp"
        shellsight_cells = "jsp/dispatch/runtime-exec-request,jsp/dispatch/runtime-exec-indirect,jsp/dispatch/processbuilder,jsp/dispatch/jspx-xml-scriptlet,jsp/channel/request-parameter,jsp/channel/header-cookie,jsp/channel/body-stream,jsp/capability/command-exec"
    strings:
        $jsp1  = "<%"
        $jsp2  = "<jsp:scriptlet"
        // Java command-exec sinks. getRuntime( is Java-specific (avoids matching embedded
        // JavaScript's regex .exec() that legit JSP views carry); ProcessBuilder is the other sink.
        $exec1 = "getRuntime(" nocase
        $exec2 = "ProcessBuilder" nocase
        // web-request input — the page is attacker-reachable
        $req1  = "getParameter" nocase
        $req2  = "getHeader" nocase
        $req3  = "getInputStream" nocase
        $req4  = "getReader(" nocase
        $req5  = "getCookies" nocase
    condition:
        filesize < 2MB and any of ($jsp*) and any of ($exec*) and any of ($req*)
}

// Shared ASPX/.NET server-page context markers ($a*) are repeated per rule (YARA has no macros):
// classic .aspx (<%@ Page), HTTP handlers (.ashx <%@ WebHandler), user controls (<%@ Control),
// and inline server code (<script runat="server">). Broader than the old "<%@ Page"-only marker,
// which missed .ashx handlers and script-runat shells.
//
// THE ANCHOR IS DERIVED FROM THE PARSER'S GRAMMAR, NOT FROM THE SPELLINGS IN OUR SAMPLES (2026-08-24).
// Every one of these anchors used to be a LITERAL -- "<%@ Page", "<%@ WebHandler", or bare "<%@" --
// and one whitespace character defeated all eleven of them at once. The shipping ASP.NET page parser
// spells the directive opener `<%\s*@`: System.Web.RegularExpressions.DirectiveRegex, read off
// System.Web.RegularExpressions.dll 4.8.4084.0 on the build host, is
//
//   \G<%\s*@(\s*(?<attrname>\w[\w:]*(?=\W))(\s*(?<equal>=)\s*"(?<attrval>[^"]*)"|\s*(?<equal>=)\s*'(?<attrval>[^']*)'|\s*(?<equal>=)\s*(?<attrval>[^\s"'%>]*)|(?<equal>)(?<attrval>\s*?)))*\s*?%>
//
// with options Multiline|Singleline. Three things follow, and all three are grammar facts rather
// than observations: whitespace between `<%` and `@` is legal; whitespace around `=` is legal; and
// the directive NAME is matched as an ordinary attrname token, so its case carries no meaning.
// `<% @ webhandler language="C#" %>` therefore compiles and serves.
//
// Measured over every staged .NET tree (1,213 malicious / 570 benign files carrying a directive):
// 18 file-instances -- 7 distinct samples -- carry ONLY the whitespace form and were invisible to
// all eleven anchors; **0 of 570 benign files carry it**. The anchor is a necessary condition ANDed
// with each rule's payload markers, so widening it can only admit files carrying the whitespace form,
// of which the benign pool holds none. Three of the seven scored 0 from all 5,872 rules before this
// change. Enumerating the observed spellings as extra literals was rejected for the same reason the
// aspx `obfuscation/escape-encoding` marker set was rejected in the 2026-08-24 marker audit: an
// enumeration of variants is defeated by the next variant, and the grammar is not.

rule aspx_eval_webshell {
    meta:
        description = "ASPX/ASP eval applied directly to request input (China-Chopper / classic-ASP eval(Request...))"
        author      = "ShellSight"
        license     = "MIT"
        family      = "GenericASPX"
        score       = "75"
        shellsight_lang = "asp-family"
        // Both branches of one regex: `eval|execute` adjacent to a request accessor. No channel
        // cell is claimed -- the pattern matches bare `request` and does not distinguish Form from
        // QueryString, so naming one would over-claim.
        shellsight_cells = "asp/dispatch/eval-request,aspx/dispatch/jscript-eval"
    strings:
        // eval/execute DIRECTLY on request input — covers both parenthesized (eval(Request...)) and
        // VBScript no-paren forms (eval request, execute request). The original rule only matched
        // eval\s*\(\s*request (requiring a paren), missing classic ASP's eval request("cmd").
        $eval = /(eval|execute)\s*(\(\s*)?request/ nocase
    condition:
        filesize < 2MB and $eval
}

rule aspx_command_exec_webshell {
    meta:
        description = "ASPX/ASP/ashx/asmx command execution: Process.Start/ProcessStartInfo in a server page"
        author      = "ShellSight"
        license     = "MIT"
        family      = "GenericASPX"
        score       = "80"
        shellsight_lang = "aspx"
        shellsight_cells = "aspx/dispatch/process-start,aspx/channel/request-accessor"
    strings:
        $a1 = /<%\s*@\s*(?:Page|WebHandler|Control|WebService)\b/ nocase
        $a4 = "<script runat" nocase
        $a5 = "runat=\"server\"" nocase
        $x1 = "Process.Start(" nocase
        $x2 = "ProcessStartInfo" nocase
        $x3 = "Diagnostics.Process" nocase
        $x4 = ".Start()" nocase
        $req = "Request" nocase
        $txt = ".Text" nocase
    condition:
        filesize < 2MB and any of ($a*) and any of ($x*) and ($req or $txt)
}

rule aspx_reflection_webshell {
    meta:
        description = "ASPX reflection / dynamic assembly loading (Assembly.Load, or GetMethod+Invoke, or CreateInstance+Invoke) on request/encoded input — Behinder/Godzilla ASPX & fileless loaders"
        author      = "ShellSight"
        license     = "MIT"
        family      = "Behinder/Godzilla-ASPX"
        score       = "80"
        shellsight_lang = "aspx"
        shellsight_cells = "aspx/dispatch/assembly-load,aspx/dispatch/reflection-late-bind,aspx/obfuscation/base64-decode"
        reference   = "https://github.com/BeichenDream/Behinder"
    strings:
        $a1 = /<%\s*@\s*(?:Page|WebHandler|Control|WebService)\b/ nocase
        $a4 = "<script runat" nocase
        $a5 = "runat=\"server\"" nocase
        $asm  = "Assembly.Load" nocase
        $getm = "GetMethod(" nocase
        $inv  = "Invoke(" nocase
        $ci   = "CreateInstance" nocase
        $req  = "Request" nocase
        $b64  = "FromBase64String" nocase
        $txt  = ".Text" nocase
    condition:
        filesize < 2MB and any of ($a*)
        and ($asm or ($getm and $inv) or ($ci and $inv))
        and ($req or $b64 or $txt)
}

rule aspx_deobfuscation_webshell {
    meta:
        description = "ASPX deobfuscation chain: FromBase64String + GZipStream/DeflateStream + Request input (compressed webshell)"
        author      = "ShellSight"
        license     = "MIT"
        family      = "GenericASPX"
        score       = "75"
        shellsight_lang = "aspx"
        shellsight_cells = "aspx/obfuscation/base64-decode,aspx/entropy/packed-blob"
    strings:
        $a1   = /<%\s*@/ nocase
        $a2   = "runat" nocase
        $b64  = "FromBase64String" nocase
        $gz   = "GZipStream" nocase
        $df   = "DeflateStream" nocase
        $req  = "Request" nocase
    condition:
        filesize < 2MB and any of ($a*) and $b64 and any of ($gz, $df) and $req
}

rule aspx_filewrite_webshell {
    meta:
        description = "ASPX/ASP file-drop / file-manager webshell: a server page writes to disk AND reads request input. Benign .NET VIEW files (.aspx/.ascx markup) don't do file I/O — it lives in code-behind — so a write sink in the markup + request input is anomalous (measured 0 FP on real-app views)."
        author      = "ShellSight"
        license     = "MIT"
        family      = "GenericASPX"
        score       = "75"
        shellsight_lang = "aspx"
        shellsight_cells = "aspx/capability/file-drop,aspx/channel/file-upload"
    strings:
        $a1 = /<%\s*@\s*(?:Page|WebHandler|Control)\b/ nocase
        $a4 = "<script runat" nocase
        $a5 = "runat=\"server\"" nocase
        $w1 = "File.WriteAll" nocase
        $w2 = "FileStream" nocase
        $w3 = "StreamWriter" nocase
        $w4 = "BinaryWriter" nocase
        $w5 = ".SaveAs(" nocase
        $req = "Request" nocase
    condition:
        filesize < 2MB and any of ($a*) and any of ($w*) and $req
}

rule china_chopper_aspx {
    meta:
        description = "China Chopper ASPX one-liner (eval + Convert.FromBase64String + Request)"
        author      = "ShellSight"
        license     = "MIT"
        family      = "ChinaChopper"
        score       = "90"
        shellsight_lang = "aspx"
        shellsight_cells = "aspx/family/china-chopper,aspx/dispatch/jscript-eval,aspx/obfuscation/base64-decode"
        reference   = "https://attack.mitre.org/software/S0020/"
    strings:
        $eval  = "eval(Request" nocase
        $b64   = "Convert.FromBase64String(" nocase
    condition:
        filesize < 50KB and $eval and $b64
}

// ─────────────────────────────────────────────────────────────────────────────
// Family attribution: Behinder (冰蝎 / "Ice Scorpion") and Godzilla (哥斯拉),
// cross-language (PHP · JSP · ASPX). RECALL on these families is already ~1.0 via the
// generic obfuscation/reflection/eval rules; these rules exist to ATTRIBUTE the family
// (ShellSight's differentiator) cleanly and KNOB-AGNOSTICALLY — measured 2026-08-13:
// generic rules catch every key/crypto variant but label them "DynamicDispatch"/
// "GenericEval"/ the ambiguous "Behinder/Godzilla-ASPX". Because recall is already
// covered, these can be strict → clean single-family labels at low FP.
//
// The two families are MUTUALLY EXCLUSIVE by one discriminator: Godzilla frames every
// response as md5(pass+key)[:16] || body || md5(pass+key)[16:] and caches the payload
// class (getBasicsInfo) in the session; Behinder uses a FIXED AES key directly, reads
// the RAW request body, and has no such framing. Behinder rules exclude the Godzilla
// markers and vice-versa, so a file attributes to at most one.
//
// Evidence (evidence-before-detector rule): Behinder key = md5("rebeyond")[:16] =
// e45e329feb5d925b, AES128 + custom ClassLoader defineClass — Sangfor "Behinder v3.0
// Analysis", CSDN 冰蝎4.0 jsp (e45e329feb5d925b), Gigamon web-shell investigation.
// Godzilla md5(pass+xc) framing + X(ClassLoader z) — nsacyber/Mitigating-Web-Shells
// (core.webshell_detection.yara), Volexity threat-intel, Malpedia jsp.godzilla_webshell.
// ─────────────────────────────────────────────────────────────────────────────

rule behinder_default_key_ioc {
    meta:
        description = "Behinder default AES key e45e329feb5d925b (= md5('rebeyond')[:16], from the developer handle 'rebeyond'). Appears verbatim in the default PHP/JSP/ASPX Behinder shell — a documented, cross-language, high-confidence family IOC. Deliberately un-gated by language: the literal is the signal."
        author      = "ShellSight"
        license     = "MIT"
        family      = "Behinder"
        score       = "90"
        reference   = "https://www.sangfor.com/blog/cybersecurity/behinder-v30-analysis"
    strings:
        $k = "e45e329feb5d925b" nocase
    condition:
        filesize < 2MB and $k
}

rule behinder_php_loader {
    meta:
        description = "Behinder PHP loader (custom-key, knob-agnostic): reads the RAW request body (php://input), AES(openssl)/XOR-decrypts it with a 16-char key, executes via eval in an __invoke/call_user_func dispatch. Godzilla reads $_POST[$pass] and frames with md5(pass+key) — both excluded here."
        author      = "ShellSight"
        license     = "MIT"
        family      = "Behinder"
        score       = "85"
        shellsight_lang = "php"
        shellsight_cells = "php/family/behinder,php/obfuscation/custom-crypt,php/channel/php-input"
        reference   = "https://ch0x01e.github.io/post/behinder/"
    strings:
        $in     = /file_get_contents\s*\(\s*["']php:\/\/input/ nocase
        $aes    = /openssl_decrypt\s*\(/ nocase
        $xoridx = /\[\s*\$?\w+\s*\+\s*1\s*&\s*15\s*\]/          // $key[$i+1&15]
        $eval   = "eval(" nocase
        $inv    = "__invoke"
        $cuf    = "call_user_func"
        // Godzilla discriminators — must be ABSENT:
        $gz1    = "getBasicsInfo"
        $gz2    = /md5\s*\(\s*\$\w+\s*\.\s*\$\w+\s*\)/          // md5($pass.$key)
    condition:
        filesize < 200KB and $in and ($aes or $xoridx) and $eval and ($inv or $cuf)
        and not ($gz1 or $gz2)
}

rule behinder_jsp_loader {
    meta:
        description = "Behinder JSP loader (custom-key, knob-agnostic): a custom ClassLoader defineClass of AES-decrypted bytecode read from the RAW request body (getReader/getInputStream). Godzilla's md5(pass+xc) framing / getBasicsInfo excluded."
        author      = "ShellSight"
        license     = "MIT"
        family      = "Behinder"
        score       = "85"
        shellsight_lang = "jsp"
        shellsight_cells = "jsp/family/behinder,jsp/dispatch/classloader-defineclass,jsp/channel/crypto-body,jsp/channel/body-stream"
        reference   = "https://blog.csdn.net/Dokii_i/article/details/135621218"
    strings:
        $def   = "defineClass" nocase
        $aes   = /Cipher\.getInstance\s*\(\s*["']AES/ nocase
        $body1 = "request.getReader()" nocase
        $body2 = "request.getInputStream()" nocase
        // Godzilla discriminators — must be ABSENT:
        $gz1   = "getBasicsInfo"
        $gz2   = /md5\s*\(\s*pass\s*\+/ nocase
    condition:
        filesize < 200KB and $def and $aes and ($body1 or $body2)
        and not ($gz1 or $gz2)
}

rule behinder_aspx_loader {
    meta:
        description = "Behinder ASPX loader: Rijndael/AES-decrypts the raw request body and Assembly.Load()s + instantiates the decrypted class (CreateInstance). The .NET Behinder AES-classloader chain (冰蝎 = Ice Scorpion, same family). Godzilla's md5(pass+key) framing / Session[\"payload\"] cache excluded. Replaces the former ambiguous ice_scorpion_aspx rule."
        author      = "ShellSight"
        license     = "MIT"
        family      = "Behinder"
        score       = "85"
        shellsight_lang = "aspx"
        shellsight_cells = "aspx/family/behinder,aspx/obfuscation/symmetric-crypt,aspx/dispatch/assembly-load,aspx/channel/request-body"
        reference   = "https://github.com/rebeyond/Behinder"
    strings:
        $a1   = /<%\s*@\s*(?:Page|WebHandler|WebService)\b/ nocase
        $a4   = "runat=\"server\"" nocase
        $a5   = "<script runat" nocase
        // actual DECRYPTION (not just the word "Rijndael", which benign crypto/config also carries)
        $dec  = "CreateDecryptor" nocase
        // dynamic LOAD of the decrypted bytes
        $asm  = "Assembly.Load" nocase
        $ci   = "CreateInstance" nocase
        // a REQUEST-BODY read feeding the decrypt (Behinder reads the raw body)
        $body1 = "BinaryRead" nocase
        $body2 = ".InputStream" nocase
        $body3 = "Request.Form" nocase
        $body4 = /Request\s*\[/ nocase
        // Godzilla discriminators — must be ABSENT:
        $gz1  = /ComputeHash[^;]{0,120}Replace\s*\(\s*"-"/ nocase
        $gz2  = /md5\s*=\s*md5\s*\(\s*pass/ nocase
        $gz3  = "Session[\"payload\"]" nocase
    condition:
        filesize < 500KB and any of ($a*) and $dec and ($asm or $ci) and any of ($body*)
        and not (any of ($gz*))
}

rule godzilla_php_loader {
    meta:
        description = "Godzilla PHP loader: caches the payload class (getBasicsInfo) in the session, XOR/AES-decrypts $_POST[$pass] with a key, eval()s it, and frames the response as md5($pass.$key)[:16] || body || [16:]. The md5(pass+key) framing + getBasicsInfo sentinel are Godzilla-unique (Behinder has neither)."
        author      = "ShellSight"
        license     = "MIT"
        family      = "Godzilla"
        score       = "85"
        shellsight_lang = "php"
        shellsight_cells = "php/family/godzilla,php/obfuscation/custom-crypt"
        reference   = "https://github.com/nsacyber/Mitigating-Web-Shells"
    strings:
        $frame  = /substr\s*\(\s*md5\s*\(\s*\$\w+\s*\.\s*\$\w+\s*\)/ nocase   // substr(md5($pass.$key)
        $basics = "getBasicsInfo"
        $sess   = /\$_SESSION\s*\[\s*\$\w+\s*\]/                             // $_SESSION[$payloadName]
        $post   = /\$_POST\s*\[\s*\$\w+\s*\]/                                // $_POST[$pass]
        $eval   = "eval(" nocase
    condition:
        filesize < 200KB and $eval and $post and ($frame or ($basics and $sess))
}

rule godzilla_jsp_loader {
    meta:
        description = "Godzilla JSP loader: the md5(pass+xc) response framing + a custom X(ClassLoader z) that defineClass'es the base64/XOR/AES-decoded payload cached in the session. Signature shape from NSA's Mitigating-Web-Shells Godzilla rule (String md5=md5(pass+xc), X(ClassLoader z))."
        author      = "ShellSight"
        license     = "MIT"
        family      = "Godzilla"
        score       = "85"
        shellsight_lang = "jsp"
        shellsight_cells = "jsp/family/godzilla,jsp/dispatch/classloader-defineclass"
        reference   = "https://github.com/nsacyber/Mitigating-Web-Shells"
    strings:
        $frame  = /md5\s*\(\s*pass\s*\+\s*xc\s*\)/ nocase
        $frame2 = /String\s+md5\s*=\s*md5\s*\(\s*pass/ nocase
        $cl     = /\w+\s*\(\s*ClassLoader\s+\w+\s*\)/                        // X(ClassLoader z)
        $def    = "defineClass" nocase
    condition:
        filesize < 200KB and ($frame or $frame2) and ($cl or $def)
}

rule godzilla_aspx_loader {
    meta:
        description = "Godzilla ASPX loader: computes md5(pass+key) (dashes stripped), Rijndael-decrypts Request[pass], caches the loaded Assembly in Session[\"payload\"], reuses it via CreateInstance, and frames the response with md5(pass+key).Substring(0,16). The md5(pass+key) framing + session-cached Assembly are Godzilla-unique vs Behinder."
        author      = "ShellSight"
        license     = "MIT"
        family      = "Godzilla"
        score       = "85"
        shellsight_lang = "aspx"
        shellsight_cells = "aspx/family/godzilla,aspx/obfuscation/symmetric-crypt,aspx/dispatch/assembly-load"
        reference   = "https://malpedia.caad.fkie.fraunhofer.de/details/jsp.godzilla_webshell"
    strings:
        $a1     = /<%\s*@\s*(?:Page|WebHandler|WebService)\b/ nocase
        $a4     = "runat=\"server\"" nocase
        $frame  = /ComputeHash[^;]{0,120}Replace\s*\(\s*"-"/ nocase          // md5(pass+key) hex, dashes stripped
        $frame2 = /md5\s*=\s*md5\s*\(\s*pass/ nocase
        $sess   = "Session[\"payload\"]" nocase
        $asm    = "Assembly" nocase
        $rij    = "Rijndael" nocase
    condition:
        filesize < 500KB and any of ($a*) and ($frame or $frame2 or $sess) and $asm and $rij
}

rule php_obfuscated_webshell {
    meta:
        description = "PHP webshell using obfuscated callable dispatch (user-controlled call_user_func, dangerous literal callable, or preg_replace /e code-exec)"
        author      = "ShellSight"
        license     = "MIT"
        family      = "GenericEval"
        score       = "75"
        shellsight_lang = "php"
        shellsight_cells = "php/dispatch/callback-sink,php/dispatch/preg-replace-e"
    strings:
        // call_user_func[_array] whose CALLABLE is taken straight from request input —
        // legit framework code passes an internal variable/property/array, never $_GET/$_POST itself.
        $cuf_userinput = /call_user_func(_array)?\s*\(\s*@?\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)/ nocase
        // call_user_func[_array] dispatching a dangerous literal function (assert/eval/system/...).
        $cuf_danger    = /call_user_func(_array)?\s*\(\s*['"](assert|eval|system|exec|passthru|shell_exec|popen|proc_open|create_function)['"]/ nocase
        // preg_replace with the (deprecated, code-executing) /e modifier — the actual modifier on the
        // pattern, NOT the bare "/e" substring that legit paths/regexes contain. Requires letters incl.
        // 'e' between the closing delimiter and the closing quote, then the next arg.
        $preg_e        = /preg_replace\s*\(\s*['"].{0,240}\/[a-zA-Z]*e[a-zA-Z]*['"]\s*,/ nocase
    condition:
        filesize < 300KB and any of them
}

rule jsp_reflection_webshell {
    meta:
        description = "JSP reflection / in-memory class loading (defineClass, or Class.forName+getMethod+invoke) on request/encoded input — Behinder/Godzilla-style JSP and class-loader droppers"
        author      = "ShellSight"
        license     = "MIT"
        family      = "GenericJSP"
        score       = "80"
        shellsight_lang = "jsp"
        shellsight_cells = "jsp/dispatch/reflection-invoke,jsp/dispatch/classloader-defineclass,jsp/obfuscation/base64-bytecode"
    strings:
        $jsp1    = "<%"
        $jsp2    = "<jsp:scriptlet"
        $def     = "defineClass" nocase
        // Same whitespace axis as jsp_classloader_webshell's $cl3, same measurement (2 malicious
        // carry only this form, 0 benign), monotone for the same reason.
        $forname = /Class\s*\.\s*forName/ nocase
        $getm    = ".getMethod(" nocase
        $inv     = ".invoke(" nocase
        $req1    = "getParameter" nocase
        $req2    = "getHeader" nocase
        $req3    = "getInputStream" nocase
        $req4    = "getReader(" nocase
        $req5    = "getCookies" nocase
        $b64     = "Base64" nocase
    condition:
        filesize < 2MB and any of ($jsp1, $jsp2)
        and ($def or ($forname and $getm and $inv))
        and (any of ($req*) or $b64)
}

rule jsp_scriptengine_webshell {
    meta:
        description = "JSP webshell using ScriptEngine (Nashorn/GraalJS) eval — bypasses Runtime.exec detection"
        author      = "ShellSight"
        license     = "MIT"
        family      = "GenericJSP"
        score       = "75"
        shellsight_lang = "jsp"
        shellsight_cells = "jsp/dispatch/scriptengine-eval"
    strings:
        $jsp = "<%"
        $se  = "ScriptEngine" nocase
        $eval = ".eval(" nocase
        // The request-accessor set is UNIFORM across every jsp rule in this file as of 2026-09-05.
        // It was not: this rule listed two accessors, jsp_reflection and jsp_classloader listed
        // three, jsp_command_exec listed four, and NONE listed getCookies. A shell reading its
        // command from the request body or a cookie was therefore invisible to three of the four
        // rules while being caught by the fourth -- the coverage difference was an artefact of
        // which rule someone last edited, not a decision. Measured on the generated jsp corpus:
        // the body and cookie channels missed here while parameter and header were caught.
        //
        // getCookies matters on its own evidence: Microsoft's 2026-04-02 write-up documents
        // cookie-gated webshells as live tradecraft, and the Servlet API exposes the same channel.
        $req1 = "getParameter" nocase
        $req2 = "getHeader" nocase
        $req3 = "getInputStream" nocase
        $req4 = "getReader(" nocase
        $req5 = "getCookies" nocase
        $b64  = "Base64" nocase
    condition:
        filesize < 2MB and $jsp and $se and $eval and (any of ($req*) or $b64)
}

rule jsp_el_injection_webshell {
    meta:
        description = "JSP webshell using Expression Language evaluation (ELProcessor/ExpressionFactory) on request input"
        author      = "ShellSight"
        license     = "MIT"
        family      = "GenericJSP"
        score       = "75"
        shellsight_lang = "jsp"
        shellsight_cells = "jsp/dispatch/el-expression"
        // WHY THIS RULE EXISTS. EL evaluation reaches Java objects directly from an expression
        // string, so a page using it contains NO execution API at all -- no Runtime, no
        // ProcessBuilder, no ScriptEngine. Every other jsp rule in this file keys on one of those,
        // which is why all four generated el-processor cells scored zero while the incumbent caught
        // them (on the bare substring 'execut' in its java alternation -- a keyword coincidence,
        // not coverage).
        //
        // PRIOR ART. CodeQL ships an experimental query for Jakarta EL injection covering both the
        // javax.el and jakarta.el packages, and the method is taint tracking from a remote source to
        // an EL evaluation sink (github/codeql#5471, retrieved 2026-09-05). Semgrep documents the
        // same source-to-sink shape for Java code injection. So the field's method here is settled
        // and it is taint, not signature; this rule is the literal-layer approximation of it and
        // pairs the sink with a request accessor in the same file rather than proving the flow.
        // A Java taint pass would be the faithful implementation and is the named next step.
    strings:
        $jsp  = "<%"
        $el1  = "ELProcessor" nocase
        $el2  = "javax.el." nocase
        $el3  = "jakarta.el." nocase
        $el4  = "ExpressionFactory" nocase
        $ev1  = ".eval(" nocase
        $ev2  = "createValueExpression" nocase
        $ev3  = "getValue(" nocase
        $req1 = "getParameter" nocase
        $req2 = "getHeader" nocase
        $req3 = "getInputStream" nocase
        $req4 = "getReader(" nocase
        $req5 = "getCookies" nocase
    condition:
        filesize < 2MB and $jsp and any of ($el*) and any of ($ev*) and any of ($req*)
}

rule jsp_classloader_webshell {
    meta:
        description = "JSP webshell using URLClassLoader/defineClass/Class.forName for remote class loading"
        author      = "ShellSight"
        license     = "MIT"
        family      = "GenericJSP"
        score       = "75"
        shellsight_lang = "jsp"
        shellsight_cells = "jsp/dispatch/classloader-defineclass,jsp/dispatch/reflection-invoke,jsp/obfuscation/base64-bytecode"
    strings:
        $jsp = "<%"
        $cl1 = "URLClassLoader" nocase
        $cl2 = "defineClass" nocase
        // Java permits whitespace, including a newline, around the `.` of a qualified name (JLS
        // 3.6: white space is permitted between tokens, and `.` is a separator token). A LITERAL
        // therefore misses a `Class` and a `.forName(...)` separated by a line break, which is
        // ordinary formatting for a long class name and not evasion. (Written in words on purpose:
        // an escaped newline inside a shell heredoc is this repo's documented editing trap and it
        // broke this very comment on the first attempt.)
        // Measured over every real jsp tree -- 606 malicious / 2,329
        // benign distinct files -- 2 malicious carry ONLY the whitespace form and 0 benign do, so
        // widening this axis adds no benign match. The old literal is a strict special case of this
        // regex, so the change is monotone: it cannot LOSE a detection.
        $cl3 = /Class\s*\.\s*forName/ nocase
        // The Apache BCEL loader's own routing constant, read off the loader rather than off our
        // samples: `private static final String BCEL_TOKEN = "$$BCEL$$"` and
        // `if (className.contains(BCEL_TOKEN)) { clazz = createClass(className); }`
        // (apache/commons-bcel ClassLoader.java, retrieved 2026-08-24; the same token exists in the
        // JDK-internal fork com.sun.org.apache.bcel.internal.util.ClassLoader). The token is
        // NECESSARY for the technique -- without it loadClass takes the ordinary path and never
        // reaches Utility.decode/defineClass -- which is what makes it a grammar constant rather
        // than a sample spelling. Measured: 4 malicious / 0 benign on the same 2,935 files.
        //
        // This is the FOURTH loader spelling; the previous three were an enumeration, and an
        // enumeration of variants is defeated by the next variant. BCEL loading was already named
        // as a bypass family in this cell's own lit review (doi:10.1155/2022/4315829) and the rule
        // did not carry it.
        $cl5 = "$$BCEL$$"
        $cl4 = "newInstance" nocase
        $req1 = "getParameter" nocase
        $req2 = "getHeader" nocase
        $req3 = "getInputStream" nocase
        $b64  = "Base64" nocase
    condition:
        filesize < 2MB and $jsp and (any of ($cl1, $cl2, $cl3, $cl5)) and any of ($cl4) and (any of ($req*) or $b64)
}

rule jsp_unicode_obfuscated_webshell {
    meta:
        description = "JSP file with high-density unicode escape sequences (\\uXXXX) — obfuscation that hides all literal patterns"
        author      = "ShellSight"
        license     = "MIT"
        family      = "GenericJSP"
        score       = "70"
        shellsight_lang = "jsp"
        shellsight_cells = "jsp/obfuscation/unicode-escape"
    strings:
        $jsp = "<%"
        $u = /\\u[0-9a-fA-F]{4}/
    condition:
        filesize < 500KB and $jsp and #u > 30
}

rule classic_asp_shell {
    meta:
        description = "Classic ASP shell using WScript.Shell or ExecuteGlobal"
        author      = "ShellSight"
        license     = "MIT"
        family      = "ClassicASP"
        score       = "75"
        shellsight_lang = "asp-family"
        // $wscript and $execgl are the two dispatch alternatives. On an ASP.NET page WScript.Shell
        // is COM interop; ExecuteGlobal has no ASP.NET form, so the aspx side claims only the one.
        shellsight_cells = "asp/dispatch/wscript-shell,asp/dispatch/executeglobal,aspx/dispatch/com-interop"
    strings:
        $wscript = "WScript.Shell" nocase
        $execgl  = "ExecuteGlobal" nocase
        $req     = "Request" nocase
    condition:
        filesize < 300KB and ($wscript or $execgl) and $req
}

rule php_command_exec_webshell {
    meta:
        description = "PHP command execution on request input (system/exec/passthru/shell_exec/proc_open/popen/pcntl_exec)"
        author      = "ShellSight"
        license     = "MIT"
        family      = "GenericCmdExec"
        score       = "75"
        shellsight_lang = "php"
        shellsight_cells = "php/dispatch/program-exec"
    strings:
        // request input passed directly into the exec call (high confidence, any size)
        $inline   = /(system|exec|passthru|shell_exec|proc_open|popen|pcntl_exec)\s*\([^;)]{0,120}\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)/ nocase
        // a command-exec sink invoked with a variable argument (request->var indirection)
        $sink_var = /(system|exec|passthru|shell_exec|proc_open|popen|pcntl_exec)\s*\(\s*@?\s*\$[a-zA-Z_]/ nocase
        // request input present somewhere in the file
        $req      = /\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)/ nocase
        $phpin    = "php://input" nocase
    condition:
        // direct case at any size; indirection case only in small files (shells are small;
        // large legit admin files that merely both exec() and read $_GET are excluded).
        // ShellSight: 50KB->30KB — WordPress core (class-wp-upgrader 49.6KB, theme 48.8KB)
        // exec internal vars just under the old gate; real indirection shells are <30KB.
        filesize < 300KB and ($inline or ($sink_var and ($req or $phpin) and filesize < 30KB))
}

rule php_obfuscated_callable_webshell {
    meta:
        description = "PHP webshell that BUILDS its callable via string obfuscation and invokes it — defeats literal eval/assert rules (the sink NAME, not just a payload, is constructed at runtime)"
        author      = "ShellSight"
        license     = "MIT"
        family      = "GenericEval"
        score       = "75"
        shellsight_lang = "php"
        shellsight_cells = "php/dispatch/variable-function,php/obfuscation/concat-split"
    strings:
        // create_function whose body is assembled with strrev (e.g. strrev('lave') = 'eval')
        $cf_strrev   = /create_function\s*\([^;]{0,200}strrev\s*\(/ nocase
        // call_user_func* + a str_replace over a base64 blob = mangled-base64 callable (WAF bypass)
        $cuf         = /call_user_func(_array)?\s*\(/ nocase
        $strrepl_b64 = /str_replace\s*\([^;)]{0,80}base64_decode/ nocase
        // variable-variable ($$x) + a variable-function call on request input
        $varvar      = /\$\$[a-zA-Z_]/
        $varfunc     = /\$[a-zA-Z_]\w*\s*\(\s*['"]?\s*\$/
        $req         = /\$_(GET|POST|REQUEST|COOKIE)/ nocase
    condition:
        filesize < 50KB and (
            $cf_strrev
            or ($cuf and $strrepl_b64)
            or ($varvar and $varfunc and $req)
        )
}

rule php_dropper_webshell {
    meta:
        description = "PHP dropper: writes a PHP file assembled from web-request input (file_put_contents/fwrite of a string containing <?php + $_REQUEST) for deferred execution"
        author      = "ShellSight"
        license     = "MIT"
        family      = "GenericEval"
        score       = "75"
        shellsight_lang = "php"
        shellsight_cells = "php/capability/file-drop"
    strings:
        // a file-write sink whose written content contains BOTH a PHP open tag and request input
        $write_phpcode = /(file_put_contents|fwrite|fputs)\s*\([^;]{0,300}<\?php[^;]{0,120}\$_(GET|POST|REQUEST|COOKIE)/ nocase
    condition:
        filesize < 50KB and $write_phpcode
}

rule php_callback_sink_webshell {
    meta:
        description = "PHP dangerous sink invoked as a STRING callback to a higher-order function with request input (array_map/call_user_func(\"assert\"...) / array_filter(..,\"system\")). The sink name is data, evading rules that match a literal sink call."
        author      = "ShellSight"
        license     = "MIT"
        family      = "GenericCallback"
        score       = "70"
        shellsight_lang = "php"
        shellsight_cells = "php/dispatch/callback-sink"
    strings:
        // dangerous sink as the callback (1st-arg form): hof("system"|"assert", ...)
        $cb_first = /\b(array_map|call_user_func(_array)?|forward_static_call(_array)?|register_(shutdown|tick)_function|iterator_apply)\s*\(\s*["'](assert|system|exec|passthru|shell_exec|popen|proc_open|pcntl_exec|eval|create_function)["']/ nocase
        // dangerous sink as a LATER-arg callback: array_filter($_..,"system") / array_udiff(..,"system") / usort(..,"assert")
        $cb_later = /\b(array_filter|array_walk(_recursive)?|array_reduce|array_udiff\w*|array_uintersect\w*|array_(diff|intersect)_u\w+|usort|uasort|uksort|preg_replace_callback)\s*\([^;]{0,160}["'](assert|system|exec|passthru|shell_exec|popen|proc_open|pcntl_exec|create_function)["']/ nocase
        // request-input reachability (benign higher-order calls with 'trim'/'intval'/etc. are excluded by the dangerous-name set above)
        $req   = /\$_(GET|POST|REQUEST|COOKIE)/ nocase
        $phpin = "php://input" nocase
    condition:
        filesize < 200KB and ($cb_first or $cb_later) and ($req or $phpin)
}

rule php_eval_concat_request_webshell {
    meta:
        description = "PHP eval/assert of a string CONCATENATED with request input (dynamic code built from user input via '.'), e.g. assert('$x='.$_REQUEST['c']). Distinct from the adjacency rule, which needs the request immediately inside eval(."
        author      = "ShellSight"
        license     = "MIT"
        family      = "GenericEval"
        score       = "75"
        shellsight_lang = "php"
        shellsight_cells = "php/dispatch/eval-request-indirect,php/obfuscation/concat-split"
    strings:
        // eval/assert( "<literal>" . $_REQUEST ... )  — request spliced into the evaluated string
        $a = /\b(eval|assert)\s*\(\s*@?\s*['"][^;]{0,200}\.\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase
        // eval/assert( $_REQUEST[..] . "<literal>" )  — request first, then concat
        $b = /\b(eval|assert)\s*\(\s*@?\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[[^\]]*\]\s*\./ nocase
    condition:
        filesize < 300KB and ($a or $b)
}

rule php_create_function_sink_webshell {
    meta:
        description = "PHP create_function whose generated body calls a dangerous sink, with request input present. create_function is deprecated and this lambda-with-sink form is near-exclusively malicious."
        author      = "ShellSight"
        license     = "MIT"
        family      = "GenericEval"
        score       = "70"
        shellsight_lang = "php"
        shellsight_cells = "php/dispatch/create-function"
    strings:
        // create_function('<args>', '<body containing a sink>')
        $cf    = /create_function\s*\(\s*['"][^'"]*['"]\s*,\s*['"][^'"]{0,200}\b(assert|eval|system|exec|passthru|shell_exec)\b/ nocase
        $req   = /\$_(GET|POST|REQUEST|COOKIE)/ nocase
        $phpin = "php://input" nocase
    condition:
        filesize < 200KB and $cf and ($req or $phpin)
}

rule aspx_interop_exec_webshell {
    meta:
        description = "ASPX webshell using P/Invoke (DllImport), ServiceProcess, or InteropServices for command execution — bypasses Process.Start detection"
        author      = "ShellSight"
        license     = "MIT"
        family      = "GenericASPX"
        score       = "75"
        shellsight_lang = "aspx"
        shellsight_cells = "aspx/dispatch/com-interop,aspx/capability/dynamic-pinvoke"
    strings:
        $a1 = /<%\s*@/ nocase
        $a2 = "runat" nocase
        $i1 = "DllImport" nocase
        $i2 = "InteropServices" nocase
        $i3 = "ServiceProcess" nocase
        $i4 = "CreateObject(" nocase
        $req = "Request" nocase
        $txt = ".Text" nocase
        $b64 = "FromBase64String" nocase
    condition:
        filesize < 2MB and any of ($a*) and any of ($i*) and ($req or $txt or $b64)
}

rule aspx_b64_eval_webshell {
    meta:
        description = "ASPX eval/execute on base64-decoded content (obfuscated request access via Convert.FromBase64String) — catches eval(Convert.FromBase64String(...)) and JScript eval(decode(...))"
        author      = "ShellSight"
        license     = "MIT"
        family      = "GenericASPX"
        score       = "80"
        shellsight_lang = "aspx"
        shellsight_cells = "aspx/obfuscation/base64-decode,aspx/dispatch/jscript-eval"
    strings:
        $a1 = /<%\s*@/ nocase
        $a2 = "runat" nocase
        $eval = /(eval|execute)\s*\(\s*[^;]{0,120}(FromBase64String|GetString|Decrypt|Decode)/ nocase
        $eval2 = /eval\s*\(/ nocase
        $b64 = "FromBase64String" nocase
    condition:
        filesize < 500KB and any of ($a*) and ($eval or ($b64 and $eval2))
}

rule aspx_filemanager_webshell {
    meta:
        description = "ASPX file-manager webshell: server page with file I/O (File.Delete/Copy/Move/Exists) + request input"
        author      = "ShellSight"
        license     = "MIT"
        family      = "GenericASPX"
        score       = "70"
        shellsight_lang = "aspx"
        shellsight_cells = "aspx/capability/file-manager"
    strings:
        $a1 = /<%\s*@/ nocase
        $a2 = "runat" nocase
        $f1 = "File.Delete" nocase
        $f2 = "File.Copy" nocase
        $f3 = "File.Move" nocase
        $f4 = "Directory.Delete" nocase
        $f5 = "File.Exists" nocase
        $req = "Request" nocase
        $txt = ".Text" nocase
    condition:
        filesize < 2MB and any of ($a*) and any of ($f*) and ($req or $txt)
}

// === GAP-FILLING RULES (from corpus miss analysis, 2026-07-03) ===

rule asp_codepage_utf7_webshell {
    meta:
        description = "ASP/ASPX using UTF-7 codepage bypass (@codepage=65000) to hide malicious code"
        author      = "ShellSight"
        license     = "MIT"
        family      = "ClassicASP"
        score       = "85"
        shellsight_lang = "asp"
        shellsight_cells = "asp/obfuscation/codepage-utf7"
    strings:
        $utf7 = "codepage=65000" nocase
    condition:
        filesize < 300KB and $utf7
}

rule asp_pct_encoded_webshell {
    meta:
        description = "ASP using %NNN percent-encoded string obfuscation (DeAsc/fun decode of %167%184... patterns)"
        author      = "ShellSight"
        license     = "MIT"
        family      = "ClassicASP"
        score       = "75"
        shellsight_lang = "asp"
        shellsight_cells = "asp/obfuscation/numeric-escape"
    strings:
        $pct = /%\d{3}%\d{3}%\d{3}/
        $exec = /(execute|eval|exec)\s*\(/ nocase
    condition:
        filesize < 300KB and $pct and $exec
}

rule asp_html_hybrid_webshell {
    meta:
        description = "ASP/ASPX webshell in HTML with a REQUEST-CONTROLLED execution or file sink"
        author      = "ShellSight"
        license     = "MIT"
        family      = "GenericASPX"
        score       = "65"
        shellsight_lang = "asp-family"
        // One cell per $rc_* branch: $rc_exec is eval/execute on request, $rc_shell is
        // WScript.Shell/Process.Start/.Run, $rc_file is a request-controlled file write. The
        // $html and $srv* strings are the surface the rule requires, not what it detects.
        shellsight_cells = "asp/dispatch/eval-request,asp/dispatch/wscript-shell,asp/capability/file-upload,aspx/dispatch/process-start,aspx/capability/file-drop"
    strings:
        $html = "<html" nocase
        $srv1 = "<%" nocase
        $srv2 = "runat=\"server\"" nocase
        $srv3 = "runat=server" nocase
        // Require the request to REACH the sink (request adjacent to the exec/file op, either
        // order, same line). Benign ASP CMS use FileSystemObject/ADODB.Stream/execute for internal
        // file I/O with the request elsewhere — measured 9 FPs on a benign classic-ASP CMS from the
        // old "sink present + Request present anywhere" condition; this drops them while keeping the
        // real request-controlled file/command shells.
        $rc_exec  = /(execute|eval)\s{0,4}\(?[^\n]{0,64}request/ nocase
        $rc_shell = /(WScript\.Shell|Process\.Start|\.Run)[^\n]{0,120}request/ nocase
        $rc_file  = /(CreateTextFile|OpenTextFile|SaveToFile|BuildPath|ADODB\.Stream|\.Write)[^\n]{0,160}request/ nocase
        $rc_rev   = /request[^\n]{0,120}(WScript\.Shell|CreateTextFile|SaveToFile|ADODB\.Stream|\.Run|\.Write|execute)/ nocase
    condition:
        filesize < 500KB and $html and any of ($srv*) and any of ($rc_*)
}

rule asp_jscript_server_webshell {
    meta:
        description = "ASP/ASPX server-side JScript with request input and execution/file sink"
        author      = "ShellSight"
        license     = "MIT"
        family      = "GenericASPX"
        score       = "70"
        shellsight_lang = "asp-family"
        // The $srv_js* strings ARE a claim here, unlike the hybrid rule above: a server-side
        // JScript block is this rule's primary discriminator, not incidental context. The
        // remaining cells are one per $rc_* branch -- eval/execute, Process.Start, Assembly.Load,
        // and the file-write alternatives.
        shellsight_cells = "aspx/surface/inline-script-runat,aspx/dispatch/jscript-eval,aspx/dispatch/process-start,aspx/dispatch/assembly-load,aspx/capability/file-drop,asp/dispatch/eval-request,asp/dispatch/wscript-shell"
    strings:
        $srv_js = /<script[^>]*runat\s*=\s*["']?server["']?[^>]*language\s*=\s*["']?(JScript|JavaScript)/ nocase
        $srv_js2 = /<script[^>]*language\s*=\s*["']?(JScript|JavaScript)["']?[^>]*runat\s*=\s*["']?server/ nocase
        // Require the request to REACH the sink -- same line, either order -- not merely to
        // co-occur somewhere in the file. The old condition was `$req and any of (sinks)` file-wide,
        // and a benign CMS admin page satisfies that trivially: a server-side JScript helper block,
        // a Request read for its own parameters, and an eval( or execute( somewhere in several
        // kilobytes of unrelated code. gh:zblogcn/zblogasp supplied 5 of this rule's benign hits and
        // was the only application that produced any.
        //
        // Measured before the change, over the Classic ASP corpus: sole detector for 0 of 349
        // malicious samples against 5 benign hits, and 0 sole detections on the ASPX, PHP, Java and
        // Perl/Python corpora either. The co-occurrence form was pure cost. This is the same fix
        // asp_html_hybrid_webshell already carries, for the same reason.
        $rc_eval  = /(eval|execute)\s{0,4}\(?[^\n]{0,64}request/ nocase
        $rc_exec  = /(WScript\.Shell|Process\.Start|Assembly\.Load)[^\n]{0,120}request/ nocase
        $rc_write = /(\.SaveAs|File\.WriteAll|StreamWriter|ADODB\.Stream)[^\n]{0,160}request/ nocase
        $rc_rev   = /request[^\n]{0,120}(eval|execute|WScript\.Shell|Process\.Start|Assembly\.Load|\.SaveAs|File\.WriteAll|StreamWriter|ADODB\.Stream)/ nocase
    condition:
        filesize < 500KB and any of ($srv_js, $srv_js2) and any of ($rc_*)
}

rule asp_dim_request_webshell {
    meta:
        description = "ASP that reads request input into a variable (dim x: x=request(...)) then has an execution/file sink — bypass-WAF minimal shells"
        author      = "ShellSight"
        license     = "MIT"
        family      = "ClassicASP"
        score       = "65"
        shellsight_lang = "asp"
        shellsight_cells = "asp/channel/request-form,asp/channel/request-querystring,asp/dispatch/eval-request"
    strings:
        $dim_req = /(dim|var)\s+\w+\s*[:,\n]\s*\w+\s*=\s*request\s*\(/ nocase
        $exec1 = "execute" nocase
        $exec2 = "eval" nocase
        $shell = "WScript.Shell" nocase
        $fso = "FileSystemObject" nocase
        $sql = "ADODB" nocase
        $create = "CreateObject" nocase
    condition:
        filesize < 100KB and $dim_req and any of ($exec1, $exec2, $shell, $fso, $sql, $create)
}

rule asp_vbscript_encoded_webshell {
    meta:
        description = "Classic ASP using VBScript.Encode obfuscation (#@~^ encoded payloads)"
        author      = "ShellSight"
        license     = "MIT"
        family      = "ClassicASP"
        score       = "80"
        shellsight_lang = "asp"
        shellsight_cells = "asp/obfuscation/vbscript-encode"
    strings:
        $encode = "VBScript.Encode" nocase
        $marker = "#@~^"
    condition:
        filesize < 300KB and $encode and $marker
}

rule asp_session_execute_webshell {
    meta:
        description = "Classic ASP storing payload in Session then executing it (execute(session(...)))"
        author      = "ShellSight"
        license     = "MIT"
        family      = "ClassicASP"
        score       = "75"
        shellsight_lang = "asp"
        shellsight_cells = "asp/obfuscation/session-staged"
    strings:
        $exec_session = /execute\s*\(\s*session/ nocase
        $req_to_sess  = /session\s*\([^)]*\)\s*=\s*request/ nocase
    condition:
        filesize < 300KB and ($exec_session or $req_to_sess)
}

rule asp_unescape_execute_webshell {
    meta:
        description = "Classic ASP execute(unescape(...)) — obfuscated eval via URL-encoded payload"
        author      = "ShellSight"
        license     = "MIT"
        family      = "ClassicASP"
        score       = "75"
        shellsight_lang = "asp"
        shellsight_cells = "asp/obfuscation/numeric-escape,asp/dispatch/eval-request"
    strings:
        $pat = /execute\s*\(\s*unescape\s*\(/ nocase
    condition:
        filesize < 300KB and $pat
}

rule asp_sql_exec_webshell {
    meta:
        description = "ASP/ASPX SQL command execution webshell (SqlConnection/ADODB.Connection + ExecuteNonQuery/Execute on request input)"
        author      = "ShellSight"
        license     = "MIT"
        family      = "GenericASPX"
        score       = "70"
        shellsight_lang = "asp-family"
        // ADODB.Connection + .Execute is the Classic ASP half; SqlConnection/SqlCommand/
        // ExecuteNonQuery is the ASP.NET half. The rule requires one of each group, so both.
        shellsight_cells = "asp/capability/database,aspx/capability/sql-client"
    strings:
        $a1 = "<%" nocase
        $sql1 = "SqlConnection" nocase
        $sql2 = "SqlCommand" nocase
        $sql3 = "ADODB.Connection" nocase
        $sql4 = "ExecuteNonQuery" nocase
        $sql5 = ".Execute(" nocase
        $sql6 = "SqlCommand" nocase
        $req = "Request" nocase
        $txt = ".Text" nocase
    condition:
        filesize < 2MB and $a1 and any of ($sql1, $sql2, $sql3) and any of ($sql4, $sql5, $sql6) and ($req or $txt)
}

rule aspx_jscript_concat_eval_webshell {
    meta:
        description = "ASPX JScript eval bypass via string concatenation with comment splitting (var P=\"e\"+\"v\"+\"a\"+\"l\"+...)"
        author      = "ShellSight"
        license     = "MIT"
        family      = "GenericASPX"
        score       = "80"
        shellsight_lang = "aspx"
        shellsight_cells = "aspx/obfuscation/escape-encoding,aspx/dispatch/jscript-eval"
    strings:
        // JScript page with string concatenation containing eval/request fragments
        $jscript = "Jscript" nocase
        $concat_eval = /["']e["']\s*\+\s*["']v["']/ nocase
        $concat_eval2 = /["']e["']\s*\/\*-?\*\/\s*\+\s*["']v["']/ nocase
    condition:
        filesize < 500KB and $jscript and ($concat_eval or $concat_eval2)
}

rule aspx_socket_webshell {
    meta:
        description = "ASPX network socket webshell (TcpListener/TcpClient/Socket + Request input) — reverse shell / port scanner"
        author      = "ShellSight"
        license     = "MIT"
        family      = "GenericASPX"
        score       = "75"
        shellsight_lang = "aspx"
        shellsight_cells = "aspx/capability/reverse-shell"
    strings:
        $a1 = /<%\s*@/ nocase
        $a2 = "runat" nocase
        $s1 = "TcpListener" nocase
        $s2 = "TcpClient" nocase
        $s3 = "System.Net.Sockets" nocase
        $s4 = "Socket(" nocase
        $req = "Request" nocase
    condition:
        filesize < 2MB and any of ($a*) and any of ($s1, $s2, $s3, $s4) and $req
}

rule php_mailer_webshell {
    meta:
        description = "PHP mass-mailer webshell (mail() with request-controlled recipient/subject/body + bulk-sending loop)"
        author      = "ShellSight"
        license     = "MIT"
        family      = "GenericCmdExec"
        score       = "65"
        shellsight_lang = "php"
        shellsight_cells = "php/capability/mass-mailer"
    strings:
        $mail = /mail\s*\(\s*[^;)]{0,120}\$_(GET|POST|REQUEST)/ nocase
        $loop = /(while|for|foreach)\s*\(/ nocase
        $req  = /\$_(GET|POST|REQUEST)/ nocase
    condition:
        filesize < 500KB and $mail and $loop and $req
}

rule php_upload_webshell {
    meta:
        description = "PHP file-upload webshell (move_uploaded_file with request-controlled destination)"
        author      = "ShellSight"
        license     = "MIT"
        family      = "GenericCmdExec"
        score       = "70"
        shellsight_lang = "php"
        shellsight_cells = "php/channel/file-upload"
    strings:
        $move = /move_uploaded_file\s*\(/ nocase
        $req  = /\$_(GET|POST|REQUEST|FILES)/ nocase
    condition:
        filesize < 300KB and $move and $req
}

rule asp_xml_xslt_webshell {
    meta:
        description = "Classic ASP XSLT-transform code execution (transformNode of a script-bearing/request-loaded stylesheet)"
        author      = "ShellSight"
        license     = "MIT"
        family      = "ClassicASP"
        score       = "70"
        shellsight_lang = "asp"
        shellsight_cells = "asp/dispatch/xslt-transform"
    strings:
        // The RCE primitive is transformNode of an XSL that carries msxsl:script / a request-loaded
        // stylesheet — NOT plain XMLDOM parsing, which is ubiquitous benign ASP. The old condition
        // (XMLDOM + Request) fired on 5 benign CMS pages and 0 malicious on the curated corpus.
        $transform = "transformNode" nocase
        $script    = /msxsl:script|xmlns:msxsl|CreateObject\s*\(\s*["']MSXML2\.XSLTemplate/ nocase
        $rc_load   = /(loadXML|\.load|stylesheet)\s{0,4}\(?[^\n]{0,80}request/ nocase
    condition:
        filesize < 300KB and $transform and ($script or $rc_load)
}

rule php_varfunc_request_webshell {
    meta:
        description = "PHP variable-function dispatch directly on request input - the sink name is held in a variable ($f=$_GET[..]; $f(..)). Anchors on the SOURCE (the superglobal) per WTA's INIT_DYNAMIC_CALL approach; literal-sink rules cannot see this."
        author      = "ShellSight"
        license     = "MIT"
        family      = "DynamicDispatch"
        score       = "75"
        shellsight_lang = "php"
        shellsight_cells = "php/dispatch/variable-function"
    strings:
        $vf = /\$\w+\s*\(\s*@?\s*\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)/ nocase
    condition:
        filesize < 50KB and $vf
}

rule php_reflection_webshell {
    meta:
        description = "PHP Reflection API used as a code-execution sink on request input - ReflectionFunction/Method OF a request-supplied name, or invoke(invokeArgs) on a request value. A genuine peer-reviewed detection gap (P4)."
        author      = "ShellSight"
        license     = "MIT"
        family      = "ReflectionSink"
        score       = "80"
        shellsight_lang = "php"
        shellsight_cells = "php/dispatch/reflection-invoke"
    strings:
        $refl_of_req = /Reflection(Function|Method)\s*\(\s*[^;)]{0,60}\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)/ nocase
        $invoke_req  = /->\s*(invoke|invokeArgs)\s*\(\s*[^;)]{0,60}\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)/ nocase
    condition:
        filesize < 300KB and ($refl_of_req or $invoke_req)
}

rule php_filter_callback_webshell {
    meta:
        description = "PHP filter_var/filter_input with FILTER_CALLBACK and a dangerous options callback (assert/system/exec/...) on request input - the callback-backdoor sink (P5)."
        author      = "ShellSight"
        license     = "MIT"
        family      = "CallbackSink"
        score       = "80"
        shellsight_lang = "php"
        shellsight_cells = "php/dispatch/callback-sink"
    strings:
        $fc   = /filter_(var|input)\s*\(\s*[^;]{0,140}FILTER_CALLBACK/ nocase
        $sink = /\b(assert|system|exec|eval|passthru|shell_exec|create_function)\b/ nocase
        $req  = /\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)/ nocase
    condition:
        filesize < 100KB and $fc and $sink and $req
}

rule php_sql_exec_webshell {
    meta:
        description = "PHP SQL execution of request input passed INTO the query call (mysql_/mysqli_/pg_/mssql_/sqlsrv_). Tightened to request-in-call: the prior co-presence form (->query( + $_GET anywhere) measured 9 FP on benign because every DB-using web app pairs ->query( with request handling."
        author      = "ShellSight"
        license     = "MIT"
        family      = "GenericSQL"
        score       = "75"
        shellsight_lang = "php"
        shellsight_cells = "php/capability/database"
    strings:
        $sink = /(mysql_query|mysqli_query|mysqli_real_query|pg_query|mssql_query|sqlsrv_query)\s*\(\s*[^;)]{0,80}\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)/ nocase
    condition:
        filesize < 100KB and $sink
}

rule php_filemanager_webshell {
    meta:
        description = "PHP file-destruction on request input (unlink/chmod with $_GET/$_POST inside the call). Restricted to unlink/chmod and request-in-call: copy/rename+co-presence measured 5 FP on benign (WordPress/phpMyAdmin) and is excluded."
        author      = "ShellSight"
        license     = "MIT"
        family      = "GenericCmdExec"
        score       = "70"
        shellsight_lang = "php"
        shellsight_cells = "php/capability/file-manager"
    strings:
        $fm = /\b(unlink|chmod)\s*\(\s*[^;)]{0,80}\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)/ nocase
    condition:
        filesize < 50KB and $fm
}

// ── Perl / Python / SSI ────────────────────────────────────────────────────────────────────
// Added 2026-08-11 to cover the languages the disk view had no rules for, grounded in a prior-art
// review of how the field detects them. Discipline mirrors the PHP rules: require an execution SINK
// in a request/CGI context, or the reverse-shell idiom — never a bare function name.
//
// That last clause is the whole design. A rule keyed on `open`, `subprocess` or `socket` alone
// matches most of the Python standard library's legitimate callers, so it cannot rank: it fires
// identically on a webshell and on a deployment script. Requiring the sink to sit in a
// request-reachable context is what makes a match mean something.

rule perl_cmd_exec_webshell {
    meta:
        description = "Perl CGI command execution reachable from request input"
        author      = "ShellSight"
        license     = "MIT"
        family      = "GenericCmdExec"
        score       = "80"
        shellsight_lang = "perl"
        shellsight_cells = "perl/dispatch/system-exec,perl/dispatch/backtick-qx,perl/dispatch/piped-open,perl/obfuscation/plaintext"
    strings:
        $sink_system = /system\s*\(/ nocase
        $sink_exec   = /\bexec\s+['"$]/ nocase
        $sink_qx     = /qx[\/{(#|!~]/ nocase
        $sink_btick  = /`[^`\n]*\$[^`\n]*`/
        $sink_popen  = /open\s*\([^)]{0,80},\s*['"][^'"]*\|['"]/ nocase
        $src_param   = /param\s*\(/ nocase
        $src_qs      = "QUERY_STRING"
        $src_cgi     = /use\s+CGI/ nocase
        $src_stdin   = /<STDIN>/
        // CGI meta-vars, not bare %ENV access (which is common in benign Perl too)
        $src_env     = /\$ENV\{['"]?(QUERY_STRING|HTTP_|REQUEST_METHOD|PATH_INFO|REMOTE_)/
    condition:
        filesize < 300KB and (any of ($sink_*)) and (any of ($src_*))
}

rule perl_reverse_shell {
    meta:
        description = "Perl reverse/bind shell: socket wired to a shell via dup'd std handles or exec"
        author      = "ShellSight"
        license     = "MIT"
        family      = "ReverseShell"
        score       = "85"
        shellsight_lang = "perl"
        shellsight_cells = "perl/capability/reverse-shell"
    strings:
        $sock = /socket\s*\(\s*\w+\s*,\s*&?(PF_INET|AF_INET)/ nocase
        $dup  = /open\s+STD(IN|OUT|ERR)\s*,\s*['"]?[<>]&/ nocase
        $sh   = /\/bin\/(sh|bash)|%COMSPEC%|cmd\.exe/ nocase
        $exec = /\bexec\b/
    condition:
        filesize < 100KB and $sock and ($dup or ($sh and $exec))
}

rule python_cmd_exec_webshell {
    meta:
        description = "Python command execution reachable from a web/CGI request"
        author      = "ShellSight"
        license     = "MIT"
        family      = "GenericCmdExec"
        score       = "80"
        shellsight_lang = "python"
        shellsight_cells = "python/dispatch/os-system,python/dispatch/subprocess-shell,python/dispatch/subprocess-argv,python/dispatch/eval,python/dispatch/exec,python/obfuscation/plaintext"
    strings:
        $s_os     = /os\.system\s*\(/
        $s_popen  = /os\.popen\d?\s*\(/
        $s_sub    = /subprocess\.(Popen|call|run|check_output|check_call)\s*\(/
        $s_eval   = /\b(eval|exec)\s*\(/
        $src_cgi  = "FieldStorage"
        $src_flask= /request\.(args|form|values|data|cookies)/
        $src_dj   = /request\.(GET|POST|body|FILES)/
        $src_qs   = "QUERY_STRING"
        $src_wsgi = "wsgi.input"
        // CGI meta-vars specifically — NOT bare os.environ access, which is ubiquitous in benign
        // code (reading PATH/HOME etc.) and was the source of 98 stdlib false positives.
        $src_env  = /environ\s*(\[|\.get\s*\()\s*['"](QUERY_STRING|HTTP_|REQUEST_METHOD|PATH_INFO|REMOTE_)/
    condition:
        filesize < 300KB and (any of ($s_*)) and (any of ($src_*))
}

rule python_reverse_shell {
    meta:
        description = "Python reverse/bind shell: socket + shell via dup2/pty/subprocess"
        author      = "ShellSight"
        license     = "MIT"
        family      = "ReverseShell"
        score       = "85"
        shellsight_lang = "python"
        shellsight_cells = "python/capability/reverse-shell"
    strings:
        $sock = /socket\.socket\s*\(/
        $dup  = /os\.dup2\s*\(/
        $pty  = /pty\.spawn\s*\(/
        $sh   = /\/bin\/(sh|bash)|cmd\.exe/ nocase
        $sub  = /subprocess\.(Popen|call)\s*\(/
    condition:
        filesize < 100KB and $sock and ($dup or $pty or ($sh and $sub))
}

rule ssi_exec_webshell {
    meta:
        description = "Server-Side Includes command execution (#exec cmd/cgi) in an SSI page"
        author      = "ShellSight"
        license     = "MIT"
        family      = "SSIExec"
        score       = "80"
        shellsight_lang = "shtml"
        shellsight_cells = "shtml/dispatch/exec-cmd,shtml/dispatch/exec-cgi"
    strings:
        // #include virtual is normal SSI and deliberately NOT flagged; #exec is the RCE surface
        $exec_cmd = /<!--\s*#\s*exec\s+cmd\s*=/ nocase
        $exec_cgi = /<!--\s*#\s*exec\s+cgi\s*=/ nocase
    condition:
        filesize < 300KB and ($exec_cmd or $exec_cgi)
}

rule php_phar_agent_webshell {
    meta:
        description = "PHP PHAR-polyglot agent: self-including phar with __HALT_COMPILER + embedded PHAR archive (Weevely3-style loader — payload hidden in the compressed PHAR, invisible to source scanning)"
        author      = "ShellSight"
        license     = "MIT"
        family      = "PharAgent"
        score       = "85"
        shellsight_lang = "php"
        shellsight_cells = "php/family/weevely"
    strings:
        $halt = "__HALT_COMPILER" nocase
        $gbmb = "GBMB"                              // PHAR manifest magic (present in every PHAR)
        // self-reference: the stub includes ITSELF as a phar (basename(__FILE__)) — the agent shape;
        // OR an explicit phar:// wrapper literal. Robust to Weevely escaping phar:// as \160\x68...
        $selfinc = /include[^;\n]{0,80}basename\s*\(\s*__FILE__/ nocase
        $phar    = "phar://" nocase
        // Phar API construction (non-self-include PHAR droppers)
        $pharapi = /(new\s+Phar|Phar::(loadPhar|mapPhar|running)|PharData::)/ nocase
    condition:
        filesize < 500KB and $halt and $gbmb and ($selfinc or $phar or $pharapi)
}
