package javadisk

import (
	"bytes"
	"encoding/xml"
	"io"
	"regexp"
	"strconv"
	"strings"
)

var (
	reJSPComment  = regexp.MustCompile(`(?s)<%--.*?--%>`)
	reServerOpen  = regexp.MustCompile(`(?i)<%(?:!|=|@)?`)
	reServerClose = regexp.MustCompile(`%>`)
	reHexEscape   = regexp.MustCompile(`\\x([0-9a-fA-F]{2})`)
	reUniEscape   = regexp.MustCompile(`\\u([0-9a-fA-F]{4})`)
)

func normalizeText(path string, data []byte) string {
	return decodeJavaEscapes(normalizeJSPText(path, data))
}

func normalizeJSPText(path string, data []byte) string {
	if strings.HasSuffix(strings.ToLower(path), ".jspx") {
		if body, collected := extractJSPXBody(data); collected {
			return body
		}
	}
	s := string(data)
	if !isJSPPath(path) {
		return s
	}
	s = reJSPComment.ReplaceAllString(s, " ")
	s = reServerOpen.ReplaceAllString(s, " ")
	return reServerClose.ReplaceAllString(s, " ")
}

func extractJSPXBody(data []byte) (string, bool) {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	decoder.Strict = false
	var body strings.Builder
	targetDepth := 0
	collected := false
	for {
		token, err := decoder.Token()
		if err != nil {
			if err == io.EOF {
				return body.String(), collected
			}
			return body.String(), collected
		}
		switch token := token.(type) {
		case xml.StartElement:
			if targetDepth > 0 {
				targetDepth++
			} else if isJSPXCodeElement(token.Name.Local) {
				targetDepth = 1
			}
		case xml.EndElement:
			if targetDepth > 0 {
				targetDepth--
			}
		case xml.CharData:
			if targetDepth > 0 {
				body.Write([]byte(token))
				collected = true
			}
		}
	}
}

func isJSPXCodeElement(local string) bool {
	switch strings.ToLower(local) {
	case "scriptlet", "declaration", "expression":
		return true
	default:
		return false
	}
}

func decodeJavaEscapes(s string) string {
	s = reUniEscape.ReplaceAllStringFunc(s, func(m string) string {
		g := reUniEscape.FindStringSubmatch(m)
		n, err := strconv.ParseInt(g[1], 16, 32)
		if err != nil {
			return m
		}
		return string(rune(n))
	})
	s = reHexEscape.ReplaceAllStringFunc(s, func(m string) string {
		g := reHexEscape.FindStringSubmatch(m)
		n, err := strconv.ParseInt(g[1], 16, 8)
		if err != nil {
			return m
		}
		return string(byte(n))
	})
	repl := strings.NewReplacer(`\"`, `"`, `\'`, `'`, `\\`, `\`, `\n`, "\n", `\r`, "\r", `\t`, "\t")
	return repl.Replace(s)
}

func isJSPPath(path string) bool {
	p := strings.ToLower(path)
	return strings.HasSuffix(p, ".jsp") || strings.HasSuffix(p, ".jspx") || strings.HasSuffix(p, ".jspf") ||
		strings.HasSuffix(p, ".jsw") || strings.HasSuffix(p, ".jsv") || strings.HasSuffix(p, ".jhtml")
}
