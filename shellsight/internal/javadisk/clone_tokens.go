package javadisk

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"hash"
	"io"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

var generatedClassSuffix = regexp.MustCompile(`(?:\$\$[^/$]+|\$[0-9a-fA-F]{6,})$`)

const jspXMLNamespace = "http://java.sun.com/JSP/Page"

// JSPCloneTokens returns literal-preserving and local-identifier-normalized
// tokens. It is deliberately independent from scanner analysis.
func JSPCloneTokens(path string, data []byte) (literal []string, structural []string, err error) {
	text, err := decodeCloneText(data)
	if err != nil {
		return nil, nil, err
	}
	if strings.HasSuffix(strings.ToLower(path), ".jspx") {
		literal, structural, err = jspxCloneTokens(text)
		if err != nil {
			return nil, nil, err
		}
		return literal, structural, nil
	}
	return jspCloneTokens(text)
}

// ClassCloneTokens parses a class with the scanner's strict parser and emits a
// resolved instruction and metadata stream with debug-only information omitted.
func ClassCloneTokens(data []byte) ([]string, error) {
	limits := DefaultOptions().Limits
	class, err := parseClass(data, limits)
	if err != nil {
		return nil, err
	}
	tokens, err := classCloneTokens(class)
	if err != nil {
		return nil, err
	}
	annotationToken, err := classAnnotationCloneToken(data, class, limits)
	if err != nil {
		return nil, err
	}
	if annotationToken != "" {
		tokens = append(tokens, annotationToken)
	}
	return tokens, nil
}

func decodeCloneText(data []byte) (string, error) {
	if len(data) >= 3 && data[0] == 0xef && data[1] == 0xbb && data[2] == 0xbf {
		data = data[3:]
		if !utf8.Valid(data) {
			return "", fmt.Errorf("invalid UTF-8 JSP input")
		}
		return string(data), nil
	}
	if len(data) >= 2 && ((data[0] == 0xff && data[1] == 0xfe) || (data[0] == 0xfe && data[1] == 0xff)) {
		if (len(data)-2)%2 != 0 {
			return "", fmt.Errorf("truncated UTF-16 JSP input")
		}
		little := data[0] == 0xff
		words := make([]uint16, 0, (len(data)-2)/2)
		for index := 2; index+1 < len(data); index += 2 {
			if little {
				words = append(words, binary.LittleEndian.Uint16(data[index:]))
			} else {
				words = append(words, binary.BigEndian.Uint16(data[index:]))
			}
		}
		for index := 0; index < len(words); index++ {
			switch {
			case words[index] >= 0xd800 && words[index] <= 0xdbff:
				if index+1 >= len(words) || words[index+1] < 0xdc00 || words[index+1] > 0xdfff {
					return "", fmt.Errorf("invalid UTF-16 surrogate at code unit %d", index)
				}
				index++
			case words[index] >= 0xdc00 && words[index] <= 0xdfff:
				return "", fmt.Errorf("invalid UTF-16 surrogate at code unit %d", index)
			}
		}
		return string(utf16.Decode(words)), nil
	}
	if !utf8.Valid(data) {
		return "", fmt.Errorf("invalid UTF-8 JSP input")
	}
	return string(data), nil
}

func jspCloneTokens(text string) (literal, structural []string, err error) {
	segments, err := splitClassicJSP(text)
	if err != nil {
		return nil, nil, err
	}
	return renderJSPCloneSegments(segments)
}

type jspCloneSegment struct {
	kind       string
	text       string
	literal    []string
	structural []string
}

func splitClassicJSP(text string) ([]jspCloneSegment, error) {
	var segments []jspCloneSegment
	for len(text) != 0 {
		start := strings.Index(text, "<%")
		if start < 0 {
			segments = append(segments, jspCloneSegment{kind: "markup", text: text})
			break
		}
		if start != 0 {
			segments = append(segments, jspCloneSegment{kind: "markup", text: text[:start]})
		}
		text = text[start:]
		if strings.HasPrefix(text, "<%--") {
			end := strings.Index(text[4:], "--%>")
			if end < 0 {
				return nil, fmt.Errorf("unterminated JSP comment")
			}
			text = text[end+8:]
			continue
		}
		end := strings.Index(text[2:], "%>")
		if end < 0 {
			return nil, fmt.Errorf("unterminated JSP server block")
		}
		body := text[2 : 2+end]
		text = text[2+end+2:]
		kind := "scriptlet"
		if len(body) > 0 {
			switch body[0] {
			case '@':
				kind, body = "directive", body[1:]
			case '!':
				kind, body = "declaration", body[1:]
			case '=':
				kind, body = "expression", body[1:]
			}
		}
		segments = append(segments, jspCloneSegment{kind: kind, text: body})
	}
	return segments, nil
}

func jspxCloneTokens(text string) (literal, structural []string, err error) {
	decoder := xml.NewDecoder(strings.NewReader(text))
	decoder.Strict = true
	var segments []jspCloneSegment
	codeDepth := 0
	codeKind := ""
	sensitiveDepth := 0
	for {
		token, err := decoder.Token()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, nil, fmt.Errorf("malformed JSPX: %w", err)
		}
		switch value := token.(type) {
		case xml.StartElement:
			name := expandedXMLName(value.Name)
			direct := jspCloneSegment{
				kind: "direct", literal: []string{"tag:" + name}, structural: []string{"tag:" + name},
			}
			for _, attr := range value.Attr {
				if attr.Name.Space == "xmlns" || (attr.Name.Space == "" && attr.Name.Local == "xmlns") {
					continue
				}
				token := "attr:" + expandedXMLName(attr.Name) + ":" + attr.Value
				direct.literal = append(direct.literal, token)
				direct.structural = append(direct.structural, token)
			}
			segments = append(segments, direct)
			if codeDepth > 0 {
				codeDepth++
			} else if isJSPXCloneCodeElement(value.Name) {
				codeDepth = 1
				codeKind = strings.ToLower(value.Name.Local)
			} else if isWhitespaceSensitiveMarkupName(value.Name.Local) {
				sensitiveDepth++
			}
		case xml.EndElement:
			if codeDepth > 0 {
				codeDepth--
				if codeDepth == 0 {
					codeKind = ""
				}
			} else if sensitiveDepth > 0 && isWhitespaceSensitiveMarkupName(value.Name.Local) {
				sensitiveDepth--
			}
		case xml.CharData:
			if codeDepth > 0 {
				segments = append(segments, jspCloneSegment{kind: codeKind, text: string(value)})
			} else {
				text := normalizedMarkupText(string(value), sensitiveDepth > 0)
				if text != "" {
					token := "html:" + text
					segments = append(segments, jspCloneSegment{
						kind: "direct", literal: []string{token}, structural: []string{token},
					})
				}
			}
		}
	}
	return renderJSPCloneSegments(segments)
}

func expandedXMLName(name xml.Name) string {
	return "{" + name.Space + "}" + name.Local
}

func isJSPXCloneCodeElement(name xml.Name) bool {
	return name.Space == jspXMLNamespace && isJSPXCodeElement(name.Local)
}

func renderJSPCloneSegments(segments []jspCloneSegment) (literal, structural []string, err error) {
	serviceNames := make([]string, 0)
	serviceSeen := make(map[string]bool)
	for _, segment := range segments {
		if segment.kind != "scriptlet" && segment.kind != "expression" {
			continue
		}
		for _, name := range cloneLocalIdentifiers(javaCloneLexemes(decodeJavaEscapes(segment.text))) {
			if !serviceSeen[name] {
				serviceSeen[name] = true
				serviceNames = append(serviceNames, name)
			}
		}
	}
	serviceLocals := cloneLocalMap(serviceNames)
	var markupState markupCloneState
	for _, segment := range segments {
		switch segment.kind {
		case "direct":
			literal = append(literal, segment.literal...)
			structural = append(structural, segment.structural...)
		case "markup":
			if err := appendMarkupCloneTokens(segment.text, &literal, &structural, &markupState); err != nil {
				return nil, nil, err
			}
		case "directive":
			literal = append(literal, "jsp:directive")
			structural = append(structural, "jsp:directive")
			appendAttributeCloneTokens(segment.text, &literal, &structural)
		case "declaration":
			literal = append(literal, "jsp:declaration")
			structural = append(structural, "jsp:declaration")
			appendDeclarationJavaCloneTokens(segment.text, &literal, &structural)
		case "scriptlet", "expression":
			literal = append(literal, "jsp:"+segment.kind)
			structural = append(structural, "jsp:"+segment.kind)
			appendJavaCloneLexemes(
				javaCloneLexemes(decodeJavaEscapes(segment.text)), serviceLocals, nil, &literal, &structural,
			)
		}
	}
	return literal, structural, nil
}

type markupCloneState struct {
	preDepth   int
	rawElement string
}

func (state *markupCloneState) preservesWhitespace() bool {
	return state.preDepth > 0 || state.rawElement != ""
}

func (state *markupCloneState) enter(name string) {
	switch name {
	case "pre":
		state.preDepth++
	case "textarea", "script", "style":
		if state.rawElement == "" {
			state.rawElement = name
		}
	}
}

func (state *markupCloneState) leave(name string) {
	if name == "pre" && state.preDepth > 0 {
		state.preDepth--
	}
	if name == state.rawElement {
		state.rawElement = ""
	}
}

func appendMarkupCloneTokens(text string, literal, structural *[]string, state *markupCloneState) error {
	for len(text) != 0 {
		start := -1
		if state.rawElement != "" {
			start = findRawMarkupClose(text, state.rawElement)
		} else {
			start = strings.IndexByte(text, '<')
		}
		if start < 0 {
			appendMarkupTextToken(text, state.preservesWhitespace(), literal, structural)
			return nil
		}
		appendMarkupTextToken(text[:start], state.preservesWhitespace(), literal, structural)
		if state.rawElement == "" && strings.HasPrefix(text[start:], "<!--") {
			end := strings.Index(text[start+4:], "-->")
			if end < 0 {
				return fmt.Errorf("unterminated HTML comment")
			}
			text = text[start+4+end+3:]
			continue
		}
		text = text[start+1:]
		end := markupTagEnd(text)
		if end < 0 {
			return fmt.Errorf("unterminated markup tag")
		}
		inside := strings.TrimSpace(text[:end])
		text = text[end+1:]
		closing := strings.HasPrefix(inside, "/")
		if closing {
			inside = strings.TrimSpace(strings.TrimPrefix(inside, "/"))
		}
		selfClosing := strings.HasSuffix(inside, "/")
		if selfClosing {
			inside = strings.TrimSpace(strings.TrimSuffix(inside, "/"))
		}
		parts := strings.Fields(inside)
		if len(parts) == 0 {
			continue
		}
		name := parts[0]
		appendTokenPair("tag", name, literal, structural)
		appendAttributeCloneTokens(strings.TrimSpace(strings.TrimPrefix(inside, name)), literal, structural)
		normalizedName := strings.ToLower(name)
		if closing {
			state.leave(normalizedName)
		} else if !selfClosing {
			state.enter(normalizedName)
		}
	}
	return nil
}

func appendMarkupTextToken(text string, preserve bool, literal, structural *[]string) {
	if normalized := normalizedMarkupText(text, preserve); normalized != "" {
		appendTokenPair("html", normalized, literal, structural)
	}
}

func normalizedMarkupText(text string, preserve bool) string {
	if preserve {
		return strings.NewReplacer("\r\n", "\n", "\r", "\n").Replace(text)
	}
	return normalizeMarkupText(text)
}

func normalizeMarkupText(text string) string {
	return strings.Join(strings.Fields(text), " ")
}

func isWhitespaceSensitiveMarkupName(name string) bool {
	switch strings.ToLower(name) {
	case "pre", "textarea", "script", "style":
		return true
	default:
		return false
	}
}

func findRawMarkupClose(text, element string) int {
	for offset := 0; offset < len(text); {
		relative := strings.IndexByte(text[offset:], '<')
		if relative < 0 {
			return -1
		}
		start := offset + relative
		nameStart := start + 2
		nameEnd := nameStart + len(element)
		if nameStart <= len(text) && text[start+1] == '/' && nameEnd <= len(text) &&
			strings.EqualFold(text[nameStart:nameEnd], element) &&
			(nameEnd == len(text) || isMarkupNameBoundary(text[nameEnd])) {
			return start
		}
		offset = start + 1
	}
	return -1
}

func isMarkupNameBoundary(value byte) bool {
	switch value {
	case ' ', '\t', '\r', '\n', '>', '/':
		return true
	default:
		return false
	}
}

func markupTagEnd(text string) int {
	var quote byte
	for index := 0; index < len(text); index++ {
		switch {
		case quote != 0 && text[index] == quote:
			quote = 0
		case quote != 0:
		case text[index] == '"' || text[index] == '\'':
			quote = text[index]
		case text[index] == '>':
			return index
		}
	}
	return -1
}

func appendAttributeCloneTokens(text string, literal, structural *[]string) {
	for _, token := range javaCloneLexemes(text) {
		if token.kind == cloneWhitespace {
			continue
		}
		appendTokenPair("attr:"+token.kind.String(), token.text, literal, structural)
	}
}

func appendTokenPair(kind, value string, literal, structural *[]string) {
	*literal = append(*literal, kind+":"+value)
	*structural = append(*structural, kind+":"+value)
}

type cloneLexemeKind uint8

const (
	cloneIdentifier cloneLexemeKind = iota
	cloneLiteral
	cloneOperator
	clonePunctuation
	cloneWhitespace
)

func (kind cloneLexemeKind) String() string {
	switch kind {
	case cloneIdentifier:
		return "id"
	case cloneLiteral:
		return "literal"
	case cloneOperator:
		return "operator"
	case clonePunctuation:
		return "punctuation"
	default:
		return "whitespace"
	}
}

type cloneLexeme struct {
	kind cloneLexemeKind
	text string
}

func cloneLocalMap(names []string) map[string]int {
	locals := make(map[string]int, len(names))
	for _, name := range names {
		if _, exists := locals[name]; !exists {
			locals[name] = len(locals)
		}
	}
	return locals
}

func appendJavaCloneLexemes(
	lexemes []cloneLexeme,
	localNames map[string]int,
	replacements map[int]string,
	literal, structural *[]string,
) {
	for index, lexeme := range lexemes {
		if lexeme.kind == cloneWhitespace {
			continue
		}
		*literal = append(*literal, "java:"+lexeme.kind.String()+":"+lexeme.text)
		value := lexeme.text
		if lexeme.kind == cloneIdentifier {
			if replacement, ok := replacements[index]; ok {
				value = replacement
			} else if number, ok := localNames[value]; ok && (index == 0 || lexemes[index-1].text != ".") {
				value = fmt.Sprintf("local:%d", number)
			}
		}
		*structural = append(*structural, "java:"+lexeme.kind.String()+":"+value)
	}
}

func appendDeclarationJavaCloneTokens(text string, literal, structural *[]string) {
	lexemes := javaCloneLexemes(decodeJavaEscapes(text))
	replacements := declarationLocalReplacements(lexemes)
	appendJavaCloneLexemes(lexemes, nil, replacements, literal, structural)
}

func javaCloneLexemes(text string) []cloneLexeme {
	var tokens []cloneLexeme
	for index := 0; index < len(text); {
		r, width := rune(text[index]), 1
		if r >= utf8RuneSelf {
			r, width = decodeRune(text[index:])
		}
		if unicode.IsSpace(r) {
			index += width
			continue
		}
		if strings.HasPrefix(text[index:], "//") {
			if end := strings.IndexByte(text[index+2:], '\n'); end >= 0 {
				index += end + 3
			} else {
				break
			}
			continue
		}
		if strings.HasPrefix(text[index:], "/*") {
			if end := strings.Index(text[index+2:], "*/"); end >= 0 {
				index += end + 4
			} else {
				break
			}
			continue
		}
		if r == '"' || r == '\'' {
			start, quote := index, byte(r)
			index++
			for index < len(text) {
				if text[index] == '\\' && index+1 < len(text) {
					index += 2
					continue
				}
				if text[index] == quote {
					index++
					break
				}
				index++
			}
			tokens = append(tokens, cloneLexeme{kind: cloneLiteral, text: text[start:index]})
			continue
		}
		if unicode.IsLetter(r) || r == '_' || r == '$' {
			start := index
			for index < len(text) {
				next, nextWidth := decodeRune(text[index:])
				if !unicode.IsLetter(next) && !unicode.IsDigit(next) && next != '_' && next != '$' {
					break
				}
				index += nextWidth
			}
			tokens = append(tokens, cloneLexeme{kind: cloneIdentifier, text: text[start:index]})
			continue
		}
		if unicode.IsDigit(r) {
			start := index
			for index < len(text) && (isCloneNumberChar(text[index]) || text[index] == '.') {
				index++
			}
			tokens = append(tokens, cloneLexeme{kind: cloneLiteral, text: text[start:index]})
			continue
		}
		operator := cloneOperatorAt(text[index:])
		kind := cloneOperator
		if strings.ContainsRune("(){}[];,.:?", r) {
			kind = clonePunctuation
		}
		tokens = append(tokens, cloneLexeme{kind: kind, text: operator})
		index += len(operator)
	}
	return tokens
}

const utf8RuneSelf = 0x80

func decodeRune(text string) (rune, int) {
	for _, r := range text {
		return r, len(string(r))
	}
	return 0, 0
}

func isCloneNumberChar(value byte) bool {
	return value >= '0' && value <= '9' || value >= 'a' && value <= 'f' || value >= 'A' && value <= 'F' || value == 'x' || value == 'X' || value == '_'
}

func cloneOperatorAt(text string) string {
	for _, operator := range []string{">>>=", "<<=", ">>=", "==", "!=", "<=", ">=", "&&", "||", "++", "--", "+=", "-=", "*=", "/=", "%=", "->", "::", "<<", ">>", ">>>"} {
		if strings.HasPrefix(text, operator) {
			return operator
		}
	}
	return text[:1]
}

func cloneLocalIdentifiers(tokens []cloneLexeme) []string {
	seen := make(map[string]bool)
	var names []string
	for index, token := range tokens {
		if token.kind != cloneIdentifier || !isCloneLocalCandidate(token.text) || seen[token.text] || index == 0 {
			continue
		}
		previous := tokens[index-1]
		if previous.text == "." || previous.kind != cloneIdentifier {
			continue
		}
		if isPrimitiveOrVar(previous.text) || startsUpper(previous.text) || (index >= 2 && tokens[index-2].text == ",") {
			seen[token.text] = true
			names = append(names, token.text)
		}
	}
	return names
}

func declarationLocalReplacements(tokens []cloneLexeme) map[int]string {
	replacements := make(map[int]string)
	for index := 1; index < len(tokens); index++ {
		if tokens[index].text != "(" || tokens[index-1].kind != cloneIdentifier || cloneBraceDepth(tokens, index) != 0 {
			continue
		}
		closeParen := matchingCloneDelimiter(tokens, index, "(", ")")
		if closeParen < 0 {
			continue
		}
		openBrace := -1
		for cursor := closeParen + 1; cursor < len(tokens); cursor++ {
			if tokens[cursor].text == ";" {
				break
			}
			if tokens[cursor].text == "{" {
				openBrace = cursor
				break
			}
		}
		if openBrace < 0 {
			continue
		}
		closeBrace := matchingCloneDelimiter(tokens, openBrace, "{", "}")
		if closeBrace < 0 {
			continue
		}
		names := append(
			cloneLocalIdentifiers(tokens[index+1:closeParen]),
			cloneLocalIdentifiers(tokens[openBrace+1:closeBrace])...,
		)
		locals := cloneLocalMap(names)
		for cursor := index + 1; cursor < closeBrace; cursor++ {
			if tokens[cursor].kind != cloneIdentifier {
				continue
			}
			number, ok := locals[tokens[cursor].text]
			if !ok || (cursor > 0 && tokens[cursor-1].text == ".") {
				continue
			}
			replacements[cursor] = fmt.Sprintf("local:%d", number)
		}
		index = closeBrace
	}
	return replacements
}

func cloneBraceDepth(tokens []cloneLexeme, before int) int {
	depth := 0
	for index := 0; index < before; index++ {
		switch tokens[index].text {
		case "{":
			depth++
		case "}":
			if depth > 0 {
				depth--
			}
		}
	}
	return depth
}

func matchingCloneDelimiter(tokens []cloneLexeme, start int, open, close string) int {
	depth := 0
	for index := start; index < len(tokens); index++ {
		switch tokens[index].text {
		case open:
			depth++
		case close:
			depth--
			if depth == 0 {
				return index
			}
		}
	}
	return -1
}

func isCloneLocalCandidate(value string) bool {
	if value == "this" || value == "super" || isPrimitiveOrVar(value) || value == "return" || value == "new" {
		return false
	}
	for _, r := range value {
		return unicode.IsLower(r) || r == '_' || r == '$'
	}
	return false
}

func isPrimitiveOrVar(value string) bool {
	switch value {
	case "byte", "short", "int", "long", "float", "double", "boolean", "char", "void", "var":
		return true
	default:
		return false
	}
}

func startsUpper(value string) bool {
	for _, r := range value {
		return unicode.IsUpper(r)
	}
	return false
}

func classCloneTokens(class *classModel) ([]string, error) {
	tokens := []string{
		fmt.Sprintf("class-access:%04x", class.Access),
		"class:" + normalizeCloneClassReference(class.Name),
		"super:" + normalizeCloneClassReference(class.Super),
	}
	interfaces := append([]string(nil), class.Interfaces...)
	sort.Strings(interfaces)
	for _, name := range interfaces {
		tokens = append(tokens, "interface:"+normalizeCloneClassReference(name))
	}
	for _, field := range class.Fields {
		tokens = append(tokens, fmt.Sprintf(
			"field:%04x:%s:%s", field.Access, field.Name, normalizeCloneDescriptor(field.Descriptor),
		))
		if field.Constant != nil {
			tokens = append(tokens, "field-constant:"+cloneConstantToken(class, *field.Constant))
		}
	}
	for _, method := range class.Methods {
		tokens = append(tokens, fmt.Sprintf(
			"method:%04x:%s:%s", method.Access, method.Name, normalizeCloneDescriptor(method.Descriptor),
		))
		if method.Code == nil {
			continue
		}
		instructions, err := decodeInstructions(method.Code.Bytes, DefaultOptions().Limits.MaxInstructions)
		if err != nil {
			return nil, fmt.Errorf("method %s%s: %w", method.Name, method.Descriptor, err)
		}
		positions := make(map[uint32]int, len(instructions))
		for index, instruction := range instructions {
			positions[instruction.Offset] = index
		}
		localSlots := make(map[uint16]int)
		for _, instruction := range instructions {
			token, err := cloneInstructionToken(class, instruction, positions, localSlots)
			if err != nil {
				return nil, fmt.Errorf("method %s%s: %w", method.Name, method.Descriptor, err)
			}
			tokens = append(tokens, token)
		}
		for _, handler := range method.Code.Handlers {
			start, ok := positions[handler.Start]
			if !ok {
				return nil, fmt.Errorf("handler start %d is not an instruction", handler.Start)
			}
			end := len(instructions)
			if handler.End != uint32(len(method.Code.Bytes)) {
				var found bool
				end, found = positions[handler.End]
				if !found {
					return nil, fmt.Errorf("handler end %d is not an instruction boundary", handler.End)
				}
			}
			target, ok := positions[handler.Handler]
			if !ok {
				return nil, fmt.Errorf("handler target %d is not an instruction", handler.Handler)
			}
			tokens = append(tokens, fmt.Sprintf("handler:%d:%d:%d:%s", start, end, target, normalizeCloneClassName(handler.CatchType)))
		}
	}
	return tokens, nil
}

type cloneAnnotationAccumulator struct {
	hash  hash.Hash
	count int
}

var errCloneAnnotationWorkBudgetExhausted = errors.New("clone annotation work budget exhausted")

type cloneAnnotationWorkBudget struct {
	remainingUnits int
	remainingBytes int64
}

func newCloneAnnotationWorkBudget(limits Limits) *cloneAnnotationWorkBudget {
	return &cloneAnnotationWorkBudget{
		remainingUnits: limits.MaxInstructions,
		remainingBytes: limits.MaxArtifactBytes,
	}
}

func (budget *cloneAnnotationWorkBudget) spendUnits(count int) error {
	if count < 0 || count > budget.remainingUnits {
		return errCloneAnnotationWorkBudgetExhausted
	}
	budget.remainingUnits -= count
	return nil
}

func (budget *cloneAnnotationWorkBudget) spendBytes(values ...string) error {
	for _, value := range values {
		size := int64(len(value))
		if size > budget.remainingBytes {
			return errCloneAnnotationWorkBudgetExhausted
		}
		budget.remainingBytes -= size
	}
	return nil
}

func (budget *cloneAnnotationWorkBudget) normalizeDescriptor(value string) (string, error) {
	if err := budget.spendBytes(value); err != nil {
		return "", err
	}
	return normalizeCloneDescriptor(value), nil
}

func (budget *cloneAnnotationWorkBudget) semanticDigest(kind string, values ...string) (string, error) {
	if err := budget.spendBytes(values...); err != nil {
		return "", err
	}
	return cloneSemanticDigest(kind, values...), nil
}

func (budget *cloneAnnotationWorkBudget) writeHashPart(hasher hash.Hash, value string) error {
	if err := budget.spendBytes(value); err != nil {
		return err
	}
	writeCloneHashPart(hasher, value)
	return nil
}

func newCloneAnnotationAccumulator() *cloneAnnotationAccumulator {
	return &cloneAnnotationAccumulator{hash: newCloneSemanticHash("class-annotations")}
}

func (accumulator *cloneAnnotationAccumulator) add(
	budget *cloneAnnotationWorkBudget,
	scope, visibility, annotation string,
) error {
	if err := budget.spendBytes(scope, visibility, annotation); err != nil {
		return err
	}
	writeCloneHashPart(accumulator.hash, scope)
	writeCloneHashPart(accumulator.hash, visibility)
	writeCloneHashPart(accumulator.hash, annotation)
	accumulator.count++
	return nil
}

func (accumulator *cloneAnnotationAccumulator) token() string {
	if accumulator.count == 0 {
		return ""
	}
	return fmt.Sprintf("annotations:%d:%s", accumulator.count, hex.EncodeToString(accumulator.hash.Sum(nil)))
}

func classAnnotationCloneToken(data []byte, class *classModel, limits Limits) (string, error) {
	budget := newCloneAnnotationWorkBudget(limits)
	reader := classReader{data: data}
	if err := reader.skip(8); err != nil {
		return "", fmt.Errorf("clone annotation class header: %w", err)
	}
	if err := skipCloneConstantPool(&reader, class, budget); err != nil {
		return "", err
	}
	if err := reader.skip(6); err != nil {
		return "", fmt.Errorf("clone annotation class declaration: %w", err)
	}
	interfaceCount, err := reader.u2()
	if err != nil {
		return "", fmt.Errorf("clone annotation interfaces_count: %w", err)
	}
	if err := ensureCountFits(&reader, interfaceCount, 2, "clone annotation interfaces"); err != nil {
		return "", err
	}
	if err := budget.spendUnits(int(interfaceCount)); err != nil {
		return "", err
	}
	if err := reader.skip(uint32(interfaceCount) * 2); err != nil {
		return "", fmt.Errorf("clone annotation interfaces: %w", err)
	}

	accumulator := newCloneAnnotationAccumulator()
	if err := scanCloneAnnotationMembers(&reader, class, limits, budget, accumulator, "field"); err != nil {
		return "", err
	}
	if err := scanCloneAnnotationMembers(&reader, class, limits, budget, accumulator, "method"); err != nil {
		return "", err
	}
	classAttributeCount, err := reader.u2()
	if err != nil {
		return "", fmt.Errorf("clone annotation class attributes_count: %w", err)
	}
	if err := scanCloneAnnotationAttributes(
		&reader, class, limits, budget, accumulator, "class", classAttributeCount,
	); err != nil {
		return "", fmt.Errorf("clone annotation class attributes: %w", err)
	}
	if reader.remaining() != 0 {
		return "", fmt.Errorf("clone annotation parser has %d trailing class bytes", reader.remaining())
	}
	return accumulator.token(), nil
}

func skipCloneConstantPool(
	reader *classReader,
	class *classModel,
	budget *cloneAnnotationWorkBudget,
) error {
	count, err := reader.u2()
	if err != nil {
		return fmt.Errorf("clone annotation constant_pool_count: %w", err)
	}
	if int(count) != len(class.Pool) {
		return fmt.Errorf("clone annotation constant-pool count %d does not match parsed count %d", count, len(class.Pool))
	}
	if err := budget.spendUnits(int(count) - 1); err != nil {
		return err
	}
	for index := uint16(1); index < count; index++ {
		tag, err := reader.u1()
		if err != nil {
			return fmt.Errorf("clone annotation constant-pool index %d: %w", index, err)
		}
		switch tag {
		case cpUtf8:
			length, err := reader.u2()
			if err != nil {
				return fmt.Errorf("clone annotation constant-pool UTF-8 index %d: %w", index, err)
			}
			if err := reader.skip(uint32(length)); err != nil {
				return fmt.Errorf("clone annotation constant-pool UTF-8 index %d: %w", index, err)
			}
		case cpInteger, cpFloat:
			err = reader.skip(4)
		case cpLong, cpDouble:
			if index+1 >= count {
				return fmt.Errorf("clone annotation constant-pool index %d has no unusable slot", index)
			}
			err = reader.skip(8)
			index++
		case cpClass, cpString, cpMethodType, cpModule, cpPackage:
			err = reader.skip(2)
		case cpFieldref, cpMethodref, cpInterfaceMethodref, cpNameAndType, cpDynamic, cpInvokeDynamic:
			err = reader.skip(4)
		case cpMethodHandle:
			err = reader.skip(3)
		default:
			return fmt.Errorf("clone annotation constant-pool index %d has invalid tag %d", index, tag)
		}
		if err != nil {
			return fmt.Errorf("clone annotation constant-pool index %d tag %d: %w", index, tag, err)
		}
	}
	return nil
}

func scanCloneAnnotationMembers(
	reader *classReader,
	class *classModel,
	limits Limits,
	budget *cloneAnnotationWorkBudget,
	accumulator *cloneAnnotationAccumulator,
	kind string,
) error {
	count, err := reader.u2()
	if err != nil {
		return fmt.Errorf("clone annotation %ss_count: %w", kind, err)
	}
	if err := ensureCountFits(reader, count, 8, "clone annotation "+kind+"s"); err != nil {
		return err
	}
	if err := budget.spendUnits(int(count)); err != nil {
		return err
	}
	for index := uint16(0); index < count; index++ {
		if _, err := reader.u2(); err != nil {
			return fmt.Errorf("clone annotation %s %d access_flags: %w", kind, index, err)
		}
		nameIndex, err := reader.u2()
		if err != nil {
			return fmt.Errorf("clone annotation %s %d name_index: %w", kind, index, err)
		}
		descriptorIndex, err := reader.u2()
		if err != nil {
			return fmt.Errorf("clone annotation %s %d descriptor_index: %w", kind, index, err)
		}
		name, err := class.utf8(nameIndex)
		if err != nil {
			return fmt.Errorf("clone annotation %s %d name_index: %w", kind, index, err)
		}
		descriptor, err := class.utf8(descriptorIndex)
		if err != nil {
			return fmt.Errorf("clone annotation %s %d descriptor_index: %w", kind, index, err)
		}
		attributeCount, err := reader.u2()
		if err != nil {
			return fmt.Errorf("clone annotation %s %d attributes_count: %w", kind, index, err)
		}
		normalizedDescriptor, err := budget.normalizeDescriptor(descriptor)
		if err != nil {
			return err
		}
		scope, err := budget.semanticDigest(
			"member-scope", kind, fmt.Sprintf("%d", index), name, normalizedDescriptor,
		)
		if err != nil {
			return err
		}
		if err := scanCloneAnnotationAttributes(
			reader, class, limits, budget, accumulator, scope, attributeCount,
		); err != nil {
			return fmt.Errorf("clone annotation %s %d attributes: %w", kind, index, err)
		}
	}
	return nil
}

func scanCloneAnnotationAttributes(
	reader *classReader,
	class *classModel,
	limits Limits,
	budget *cloneAnnotationWorkBudget,
	accumulator *cloneAnnotationAccumulator,
	scope string,
	count uint16,
) error {
	if err := ensureCountFits(reader, count, 6, "clone annotation attributes"); err != nil {
		return err
	}
	if err := budget.spendUnits(int(count)); err != nil {
		return err
	}
	for index := uint16(0); index < count; index++ {
		name, attribute, err := readAttribute(reader, class)
		if err != nil {
			return fmt.Errorf("attribute %d: %w", index, err)
		}
		switch name {
		case "RuntimeVisibleAnnotations", "RuntimeInvisibleAnnotations":
			if err := scanCloneTypedAnnotations(
				attribute, class, limits, budget, accumulator, scope, name,
			); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			if err := ensureAttributeConsumed(name, attribute); err != nil {
				return err
			}
		}
	}
	return nil
}

func scanCloneTypedAnnotations(
	reader *classReader,
	class *classModel,
	limits Limits,
	budget *cloneAnnotationWorkBudget,
	accumulator *cloneAnnotationAccumulator,
	scope, visibility string,
) error {
	count, err := reader.u2()
	if err != nil {
		return err
	}
	if err := ensureCountFits(reader, count, 4, "clone annotations"); err != nil {
		return err
	}
	for index := uint16(0); index < count; index++ {
		annotation, err := parseCloneTypedAnnotation(reader, class, limits, budget, 1)
		if err != nil {
			return fmt.Errorf("annotation %d: %w", index, err)
		}
		if err := accumulator.add(budget, scope, visibility, annotation); err != nil {
			return err
		}
	}
	return nil
}

func parseCloneTypedAnnotation(
	reader *classReader,
	class *classModel,
	limits Limits,
	budget *cloneAnnotationWorkBudget,
	depth int,
) (string, error) {
	if depth > limits.MaxAnnotationDepth {
		return "", fmt.Errorf("annotation nesting depth %d exceeds limit %d", depth, limits.MaxAnnotationDepth)
	}
	if err := budget.spendUnits(1); err != nil {
		return "", err
	}
	descriptorIndex, err := reader.u2()
	if err != nil {
		return "", err
	}
	descriptor, err := class.utf8(descriptorIndex)
	if err != nil {
		return "", fmt.Errorf("type_index: %w", err)
	}
	pairCount, err := reader.u2()
	if err != nil {
		return "", err
	}
	if err := ensureCountFits(reader, pairCount, 3, "clone annotation element pairs"); err != nil {
		return "", err
	}
	if err := budget.spendUnits(int(pairCount)); err != nil {
		return "", err
	}
	elements := make([]string, 0, pairCount)
	for index := uint16(0); index < pairCount; index++ {
		nameIndex, err := reader.u2()
		if err != nil {
			return "", err
		}
		name, err := class.utf8(nameIndex)
		if err != nil {
			return "", fmt.Errorf("element pair %d name_index: %w", index, err)
		}
		value, err := parseCloneTypedAnnotationValue(reader, class, limits, budget, depth)
		if err != nil {
			return "", fmt.Errorf("element pair %d: %w", index, err)
		}
		element, err := budget.semanticDigest("annotation-element", name, value)
		if err != nil {
			return "", err
		}
		elements = append(elements, element)
	}
	sort.Strings(elements)
	normalizedDescriptor, err := budget.normalizeDescriptor(descriptor)
	if err != nil {
		return "", err
	}
	hasher := newCloneSemanticHash("annotation")
	if err := budget.writeHashPart(hasher, normalizedDescriptor); err != nil {
		return "", err
	}
	if err := budget.writeHashPart(hasher, fmt.Sprintf("%d", len(elements))); err != nil {
		return "", err
	}
	for _, element := range elements {
		if err := budget.writeHashPart(hasher, element); err != nil {
			return "", err
		}
	}
	return string(hasher.Sum(nil)), nil
}

func parseCloneTypedAnnotationValue(
	reader *classReader,
	class *classModel,
	limits Limits,
	budget *cloneAnnotationWorkBudget,
	depth int,
) (string, error) {
	if depth > limits.MaxAnnotationDepth {
		return "", fmt.Errorf("annotation nesting depth %d exceeds limit %d", depth, limits.MaxAnnotationDepth)
	}
	if err := budget.spendUnits(1); err != nil {
		return "", err
	}
	tag, err := reader.u1()
	if err != nil {
		return "", err
	}
	switch tag {
	case 'B', 'C', 'D', 'F', 'I', 'J', 'S', 'Z':
		index, err := reader.u2()
		if err != nil {
			return "", err
		}
		value, err := annotationPrimitive(class, index, tag)
		if err != nil {
			return "", err
		}
		return budget.semanticDigest(
			"annotation-primitive", string(rune(tag)), fmt.Sprintf("%016x", uint64(value.Integer)),
		)
	case 's':
		index, err := reader.u2()
		if err != nil {
			return "", err
		}
		value, err := class.utf8(index)
		if err != nil {
			return "", fmt.Errorf("string const_value_index: %w", err)
		}
		return budget.semanticDigest("annotation-string", value)
	case 'e':
		typeIndex, err := reader.u2()
		if err != nil {
			return "", err
		}
		nameIndex, err := reader.u2()
		if err != nil {
			return "", err
		}
		typeName, err := class.utf8(typeIndex)
		if err != nil {
			return "", fmt.Errorf("enum type_name_index: %w", err)
		}
		name, err := class.utf8(nameIndex)
		if err != nil {
			return "", fmt.Errorf("enum const_name_index: %w", err)
		}
		normalizedType, err := budget.normalizeDescriptor(typeName)
		if err != nil {
			return "", err
		}
		return budget.semanticDigest("annotation-enum", normalizedType, name)
	case 'c':
		index, err := reader.u2()
		if err != nil {
			return "", err
		}
		classInfo, err := class.utf8(index)
		if err != nil {
			return "", fmt.Errorf("class_info_index: %w", err)
		}
		normalizedClass, err := budget.normalizeDescriptor(classInfo)
		if err != nil {
			return "", err
		}
		return budget.semanticDigest("annotation-class", normalizedClass)
	case '@':
		annotation, err := parseCloneTypedAnnotation(reader, class, limits, budget, depth+1)
		if err != nil {
			return "", err
		}
		return budget.semanticDigest("annotation-nested", annotation)
	case '[':
		if depth+1 > limits.MaxAnnotationDepth {
			return "", fmt.Errorf("annotation nesting depth %d exceeds limit %d", depth+1, limits.MaxAnnotationDepth)
		}
		count, err := reader.u2()
		if err != nil {
			return "", err
		}
		if err := ensureCountFits(reader, count, 1, "clone annotation array values"); err != nil {
			return "", err
		}
		hasher := newCloneSemanticHash("annotation-array")
		if err := budget.writeHashPart(hasher, fmt.Sprintf("%d", count)); err != nil {
			return "", err
		}
		for index := uint16(0); index < count; index++ {
			value, err := parseCloneTypedAnnotationValue(reader, class, limits, budget, depth+1)
			if err != nil {
				return "", fmt.Errorf("array element %d: %w", index, err)
			}
			if err := budget.writeHashPart(hasher, value); err != nil {
				return "", err
			}
		}
		return string(hasher.Sum(nil)), nil
	default:
		return "", fmt.Errorf("invalid annotation element tag 0x%02x", tag)
	}
}

func newCloneSemanticHash(kind string) hash.Hash {
	hasher := sha256.New()
	writeCloneHashPart(hasher, "shellsight-class-clone-v1")
	writeCloneHashPart(hasher, kind)
	return hasher
}

func cloneSemanticDigest(kind string, values ...string) string {
	hasher := newCloneSemanticHash(kind)
	for _, value := range values {
		writeCloneHashPart(hasher, value)
	}
	return string(hasher.Sum(nil))
}

func writeCloneHashPart(hasher hash.Hash, value string) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = hasher.Write(length[:])
	_, _ = io.WriteString(hasher, value)
}

func cloneFramedStrings(values []string) string {
	var framed strings.Builder
	fmt.Fprintf(&framed, "%d:", len(values))
	for _, value := range values {
		fmt.Fprintf(&framed, "%d:", len(value))
		framed.WriteString(value)
	}
	return framed.String()
}

func normalizeCloneClassName(name string) string {
	return generatedClassSuffix.ReplaceAllString(name, "$$generated")
}

func normalizeCloneClassReference(name string) string {
	if strings.Contains(name, "L") && strings.Contains(name, ";") {
		return normalizeCloneDescriptor(name)
	}
	return normalizeCloneClassName(name)
}

func normalizeCloneDescriptor(descriptor string) string {
	var normalized strings.Builder
	for start := 0; start < len(descriptor); {
		if descriptor[start] != 'L' {
			normalized.WriteByte(descriptor[start])
			start++
			continue
		}
		end := strings.IndexByte(descriptor[start:], ';')
		if end < 0 {
			normalized.WriteString(descriptor[start:])
			break
		}
		end += start
		normalized.WriteByte('L')
		normalized.WriteString(normalizeCloneClassName(descriptor[start+1 : end]))
		normalized.WriteByte(';')
		start = end + 1
	}
	return normalized.String()
}

func cloneInstructionToken(class *classModel, instruction instruction, positions map[uint32]int, localSlots map[uint16]int) (string, error) {
	prefix := fmt.Sprintf("op:%02x", instruction.Opcode)
	if token, ok := cloneLocalInstructionToken(instruction, localSlots); ok {
		return token, nil
	}
	if instruction.Opcode == 0xaa || instruction.Opcode == 0xab {
		return cloneSwitchInstructionToken(instruction, positions)
	}
	if len(instruction.Targets) != 0 {
		targets := make([]string, 0, len(instruction.Targets))
		for _, target := range instruction.Targets {
			position, ok := positions[target]
			if !ok {
				return "", fmt.Errorf("branch target %d is not an instruction", target)
			}
			targets = append(targets, fmt.Sprintf("%d", position))
		}
		return prefix + ":targets:" + strings.Join(targets, ","), nil
	}
	index, hasIndex := cloneConstantPoolIndex(instruction)
	if hasIndex {
		switch instruction.Opcode {
		case 0x12, 0x13, 0x14:
			constant, err := class.constantValue(index)
			if err != nil {
				return "", err
			}
			return prefix + ":constant:" + cloneConstantToken(class, constant), nil
		case 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9:
			reference, err := class.memberRef(index)
			if err != nil {
				return "", err
			}
			return prefix + ":member:" + cloneMemberToken(reference), nil
		case 0xba:
			return cloneInvokeDynamicToken(class, index, prefix)
		case 0xbb, 0xbd, 0xc0, 0xc1, 0xc5:
			name, err := class.className(index)
			if err != nil {
				return "", err
			}
			token := prefix + ":class:" + normalizeCloneClassReference(name)
			if instruction.Opcode == 0xc5 {
				token += fmt.Sprintf(":dimensions:%d", instruction.Operands[2])
			}
			return token, nil
		}
	}
	if len(instruction.Operands) == 0 {
		return prefix, nil
	}
	return prefix + ":operands:" + hex.EncodeToString(instruction.Operands), nil
}

func cloneSwitchInstructionToken(instruction instruction, positions map[uint32]int) (string, error) {
	padding := int((4 - (instruction.Offset+1)%4) % 4)
	body := padding
	if len(instruction.Operands) < body+8 {
		return "", fmt.Errorf("truncated switch operands")
	}
	targets := make([]string, 0, len(instruction.Targets))
	for _, target := range instruction.Targets {
		position, ok := positions[target]
		if !ok {
			return "", fmt.Errorf("switch target %d is not an instruction", target)
		}
		targets = append(targets, fmt.Sprintf("%d", position))
	}
	if instruction.Opcode == 0xaa {
		if len(instruction.Operands) < body+12 {
			return "", fmt.Errorf("truncated tableswitch operands")
		}
		low := int32(binary.BigEndian.Uint32(instruction.Operands[body+4 : body+8]))
		high := int32(binary.BigEndian.Uint32(instruction.Operands[body+8 : body+12]))
		return fmt.Sprintf(
			"op:aa:low:%d:high:%d:targets:%s", low, high, strings.Join(targets, ","),
		), nil
	}
	count := int(int32(binary.BigEndian.Uint32(instruction.Operands[body+4 : body+8])))
	if count < 0 || len(instruction.Operands) < body+8+count*8 {
		return "", fmt.Errorf("invalid lookupswitch operands")
	}
	keys := make([]string, 0, count)
	for index := 0; index < count; index++ {
		offset := body + 8 + index*8
		key := int32(binary.BigEndian.Uint32(instruction.Operands[offset : offset+4]))
		keys = append(keys, fmt.Sprintf("%d", key))
	}
	return "op:ab:keys:" + strings.Join(keys, ",") + ":targets:" + strings.Join(targets, ","), nil
}

func cloneInvokeDynamicToken(class *classModel, index uint16, prefix string) (string, error) {
	reference, err := class.invokeDynamic(index)
	if err != nil {
		return "", err
	}
	bootstrap, err := cloneBootstrapToken(class, reference.Bootstrap, 0)
	if err != nil {
		return "", err
	}
	return prefix + ":dynamic:" + reference.Name + ":" + normalizeCloneDescriptor(reference.Descriptor) + ":" + bootstrap, nil
}

func cloneBootstrapToken(class *classModel, index uint16, depth int) (string, error) {
	if int(index) >= len(class.Bootstraps) {
		return "", fmt.Errorf("bootstrap index %d out of range", index)
	}
	if depth > len(class.Bootstraps) {
		return "bootstrap-cycle", nil
	}
	bootstrap := class.Bootstraps[index]
	arguments := make([]string, 0, len(bootstrap.Arguments))
	for _, argument := range bootstrap.Arguments {
		arguments = append(arguments, cloneConstantTokenDepth(class, argument, depth+1))
	}
	return fmt.Sprintf(
		"bootstrap:%d:%s:arguments:%s",
		bootstrap.HandleKind, cloneMemberToken(bootstrap.Handle), cloneFramedStrings(arguments),
	), nil
}

func cloneLocalInstructionToken(instruction instruction, localSlots map[uint16]int) (string, bool) {
	var slot uint16
	kind := ""
	switch {
	case instruction.Opcode >= 0x15 && instruction.Opcode <= 0x19 && len(instruction.Operands) == 1:
		kind, slot = fmt.Sprintf("load:%02x", instruction.Opcode-0x15), uint16(instruction.Operands[0])
	case instruction.Opcode >= 0x36 && instruction.Opcode <= 0x3a && len(instruction.Operands) == 1:
		kind, slot = fmt.Sprintf("store:%02x", instruction.Opcode-0x36), uint16(instruction.Operands[0])
	case instruction.Opcode >= 0x1a && instruction.Opcode <= 0x2d:
		kind, slot = fmt.Sprintf("load:%02x", (instruction.Opcode-0x1a)/4), uint16((instruction.Opcode-0x1a)%4)
	case instruction.Opcode >= 0x3b && instruction.Opcode <= 0x4e:
		kind, slot = fmt.Sprintf("store:%02x", (instruction.Opcode-0x3b)/4), uint16((instruction.Opcode-0x3b)%4)
	case instruction.Opcode == 0x84 && len(instruction.Operands) == 2:
		kind, slot = fmt.Sprintf("iinc:%d", int8(instruction.Operands[1])), uint16(instruction.Operands[0])
	case instruction.Opcode == 0xa9 && len(instruction.Operands) == 1:
		kind, slot = "ret", uint16(instruction.Operands[0])
	case instruction.Opcode == 0xc4 && len(instruction.Operands) >= 3:
		subopcode := instruction.Operands[0]
		slot = binary.BigEndian.Uint16(instruction.Operands[1:3])
		switch {
		case subopcode >= 0x15 && subopcode <= 0x19:
			kind = fmt.Sprintf("wide-load:%02x", subopcode-0x15)
		case subopcode >= 0x36 && subopcode <= 0x3a:
			kind = fmt.Sprintf("wide-store:%02x", subopcode-0x36)
		case subopcode == 0x84 && len(instruction.Operands) == 5:
			kind = fmt.Sprintf("wide-iinc:%d", int16(binary.BigEndian.Uint16(instruction.Operands[3:5])))
		case subopcode == 0xa9:
			kind = "wide-ret"
		default:
			return "", false
		}
	default:
		return "", false
	}
	canonical, ok := localSlots[slot]
	if !ok {
		canonical = len(localSlots)
		localSlots[slot] = canonical
	}
	return fmt.Sprintf("%s:local:%d", kind, canonical), true
}

func cloneConstantPoolIndex(instruction instruction) (uint16, bool) {
	if len(instruction.Operands) == 0 {
		return 0, false
	}
	if instruction.Opcode == 0x12 {
		return uint16(instruction.Operands[0]), true
	}
	if len(instruction.Operands) >= 2 {
		return binary.BigEndian.Uint16(instruction.Operands), true
	}
	return 0, false
}

func cloneConstantToken(class *classModel, value constantValue) string {
	return cloneConstantTokenDepth(class, value, 0)
}

func cloneConstantTokenDepth(class *classModel, value constantValue, depth int) string {
	switch value.Kind {
	case constantString:
		return "string:" + value.String
	case constantInteger:
		return fmt.Sprintf("integer:%d", value.Integer)
	case constantFloat:
		return fmt.Sprintf("float:%d", value.Integer)
	case constantLong:
		return fmt.Sprintf("long:%d", value.Integer)
	case constantDouble:
		return fmt.Sprintf("double:%d", value.Integer)
	case constantClass:
		return "class:" + normalizeCloneClassReference(value.String)
	case constantMethodType:
		return "method-type:" + normalizeCloneDescriptor(value.String)
	case constantMethodHandle:
		if value.Reference != nil {
			return fmt.Sprintf("method-handle:%d:%s", value.HandleKind, cloneMemberToken(*value.Reference))
		}
	case constantDynamic:
		if value.Reference != nil {
			bootstrap, err := cloneBootstrapToken(class, value.Bootstrap, depth+1)
			if err != nil {
				return "dynamic-error:" + err.Error()
			}
			return "dynamic:" + value.Reference.Name + ":" +
				normalizeCloneDescriptor(value.Reference.Descriptor) + ":" + bootstrap
		}
	}
	return fmt.Sprintf("kind:%d", value.Kind)
}

func cloneMemberToken(reference memberReference) string {
	return fmt.Sprintf(
		"%s:%s:%s:interface:%t",
		normalizeCloneClassReference(reference.Owner),
		reference.Name,
		normalizeCloneDescriptor(reference.Descriptor),
		reference.Interface,
	)
}
