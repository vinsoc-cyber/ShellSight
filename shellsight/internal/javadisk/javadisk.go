package javadisk

import (
	"regexp"
	"strconv"
	"strings"
)

type Finding struct {
	Score        int
	Family       string
	Rule         string
	Evidence     string
	ArtifactPath string
}

func Analyze(path string, data []byte) []Finding {
	text := strings.ToLower(stripJavaComments(normalizeAnalyzerText(path, data)))
	var out []Finding
	state := newAnalyzerState(isJSPPath(path))
	hasRequestExec, hasFileDrop, hasClassloadInput := false, false, false
	hasScriptEval, hasReflectionInput, hasReverseShell := false, false, false
	hasRequestInput, hasDeserialization, hasJNDILookup := false, false, false
	hasHookRegistration := false

	for _, segment := range javaStatements(text) {
		if segment.boundary == '{' {
			state.pushScope()
		}
		statement := strings.TrimSpace(segment.text)
		if statement == "" {
			if segment.boundary == '}' {
				state.popScope()
			}
			continue
		}

		state.discoverTypedReceivers(statement)
		if hasRequestSourceCall(statement, state.requestReceivers) {
			hasRequestInput = true
		}
		if hasExecSink(statement) && processExecutionArgumentsInputControlled(statement, state) {
			hasRequestExec = true
		}
		if hasExecSink(statement) && executionArgumentsContainReverseShell(statement, state.constantStrings) {
			hasReverseShell = true
		}
		if fileWriteReceivesInput(statement, state) {
			hasFileDrop = true
		}
		if hasClassloadSink(statement) && sinkArgumentsInputControlled(statement, []string{".defineclass("}, state) {
			hasClassloadInput = true
		}
		if scriptEvaluationReceivesInput(statement, state) {
			hasScriptEval = true
		}
		if hasReflectionSink(statement) && sinkArgumentsInputControlled(statement, []string{".invoke("}, state) {
			hasReflectionInput = true
		}
		if hasRemoteJNDILookup(statement, state.jndiContexts) {
			hasJNDILookup = true
		}
		if hasDeserializationContext(statement, state.objectInputStreams) {
			hasDeserialization = true
		}
		if hasServletHookRegistration(statement, state.servletContexts) {
			hasHookRegistration = true
		}

		if parsed, ok := parseAssignment(statement); ok {
			facts := deriveAssignmentFacts(parsed, state)
			if parsed.declaredType != "" {
				state.declare(parsed.name)
			}
			state.assign(parsed.name, facts)
		}
		if segment.boundary == '}' {
			state.popScope()
		}
	}

	code := stripJavaStrings(text)
	hasClassLoad := hasClassloadInput ||
		(strings.Contains(code, ".defineclass(") && containsAny(code, []string{"base64", "cafebabe", "yv66vg"}))
	hasDeserJNDI := hasDeserialization || hasJNDILookup

	switch {
	case hasRequestExec:
		out = append(out, Finding{Score: 85, Family: "GenericJSP", Rule: "javadisk:request-exec", Evidence: "Java/JSP source reads request input and reaches Runtime.exec/ProcessBuilder"})
	case hasReverseShell && isJavaOrJSPPath(path):
		out = append(out, Finding{Score: 40, Family: "GenericJSP", Rule: "javadisk:reverse-shell-literal", Evidence: "Java/JSP source contains reverse-shell command literal"})
	}
	if hasFileDrop {
		out = append(out, Finding{Score: 85, Family: "FileDrop", Rule: "javadisk:file-drop-on-request", Evidence: "Java/JSP source writes request-controlled data to executable web/class path"})
	}
	if hasClassLoad {
		score := 75
		if hasClassloadInput {
			score = 85
		}
		out = append(out, Finding{Score: score, Family: "DynamicClassload", Rule: "javadisk:dynamic-classload", Evidence: "Java/JSP source combines classloader/defineClass with request or encoded bytecode"})
	}
	if hasScriptEval {
		out = append(out, Finding{Score: 75, Family: "ScriptEngine", Rule: "javadisk:scriptengine-eval", Evidence: "Java/JSP source evaluates request-controlled data through ScriptEngine/Groovy/OGNL/MVEL"})
	}
	if hasReflectionInput {
		out = append(out, Finding{Score: 75, Family: "Reflection", Rule: "javadisk:reflection-invoke", Evidence: "Java/JSP source uses request-controlled reflection invoke chain"})
	}
	if hasDeserJNDI && (hasRequestInput || isJSPPath(path)) {
		out = append(out, Finding{Score: 60, Family: "DeserializationJNDI", Rule: "javadisk:deserialization-jndi", Evidence: "Java/JSP source contains deserialization or JNDI lookup pattern"})
	}
	if hasHookRegistration && isJSPPath(path) {
		out = append(out, Finding{Score: 60, Family: "MemshellDropper", Rule: "javadisk:servlet-hook-registration", Evidence: "JSP source manipulates servlet/filter/listener/Spring registration APIs"})
	}
	return out
}

var (
	reIdentifier                 = regexp.MustCompile(`[a-z_$][a-z0-9_$]*`)
	reTrailingIdentifier         = regexp.MustCompile(`[a-z_$][a-z0-9_$]*\s*$`)
	reExactIdentifier            = regexp.MustCompile(`^[a-z_$][a-z0-9_$]*$`)
	reReceiverCall               = regexp.MustCompile(`([a-z_$][a-z0-9_$]*)\s*\.\s*([a-z_$][a-z0-9_$]*)\s*\(`)
	rePageContextRequest         = regexp.MustCompile(`(?:^|[^a-z0-9_$])pagecontext\s*\.\s*getrequest\s*\(`)
	reGetServletContext          = regexp.MustCompile(`(?:^|[^a-z0-9_$])(?:[a-z_$][a-z0-9_$]*\s*\.\s*)?getservletcontext\s*\(`)
	reNewInitialContext          = regexp.MustCompile(`(?:^|[^a-z0-9_$])new\s+(?:[a-z_$][a-z0-9_$]*\s*\.\s*)*initialcontext\s*\(`)
	reDirectInitialContextLookup = regexp.MustCompile(`(?:^|[^a-z0-9_$])new\s+(?:[a-z_$][a-z0-9_$]*\s*\.\s*)*initialcontext\s*\([^)]*\)\s*\.\s*lookup\s*\(`)
	reNewObjectInputStream       = regexp.MustCompile(`(?:^|[^a-z0-9_$])new\s+(?:[a-z_$][a-z0-9_$]*\s*\.\s*)*objectinputstream\s*\(`)
	reNewScriptEngineManager     = regexp.MustCompile(`(?:^|[^a-z0-9_$])new\s+(?:[a-z_$][a-z0-9_$]*\s*\.\s*)*scriptenginemanager\s*\(`)
	reRuntimeExecCall            = regexp.MustCompile(`(?:^|[^a-z0-9_$])runtime\s*\.\s*getruntime\s*\(\s*\)\s*\.\s*exec\s*\(`)
	reProcessBuilderCall         = regexp.MustCompile(`(?:^|[^a-z0-9_$])new\s+(?:[a-z_$][a-z0-9_$]*\s*\.\s*)*processbuilder\s*\(`)
	reTypedReceiverDeclaration   = regexp.MustCompile(`(?:^|[^a-z0-9_$])(?:[a-z_$][a-z0-9_$]*\s*\.\s*)*(httpservletrequest|servletrequest|objectinputstream|groovyshell)\s+([a-z_$][a-z0-9_$]*)`)
)

var executablePathExtensions = []string{".jsp", ".jspx", ".jspf", ".class", ".jar"}
var executablePathDirectories = []string{"web-inf/classes", "web-inf/lib"}
var reverseShellLiterals = []string{"/dev/tcp/", "bash -i", "cmd.exe", "powershell"}
var requestSourceMethods = map[string]bool{
	"getparameter":       true,
	"getparametermap":    true,
	"getparametervalues": true,
	"getheader":          true,
	"getheaders":         true,
	"getcookies":         true,
	"getinputstream":     true,
	"getreader":          true,
}
var fileWriterConstructorPrefixes = []string{"fileoutputstream(", "filewriter(", "streamwriter("}

var servletHookMethods = map[string]bool{
	"addfilter":                   true,
	"addservlet":                  true,
	"addinterceptor":              true,
	"addlistener":                 true,
	"addapplicationeventlistener": true,
	"addmappingforurlpatterns":    true,
}

type analyzerState struct {
	tainted              map[string]bool
	executablePaths      map[string]bool
	executableWriters    map[string]bool
	scriptEngineManagers map[string]bool
	scriptEngines        map[string]bool
	groovyShells         map[string]bool
	requestReceivers     map[string]bool
	objectInputStreams   map[string]bool
	jndiContexts         map[string]bool
	servletContexts      map[string]bool
	constantStrings      map[string]string
	typedRequest         map[string]bool
	typedObjectInput     map[string]bool
	typedGroovyShell     map[string]bool
	scopes               []analyzerScope
	allowJSPPageContext  bool
}

type analyzerScope struct {
	declarations map[string]scopedNameFacts
}

type scopedNameFacts struct {
	tainted             bool
	executablePath      bool
	executableWriter    bool
	scriptEngineManager bool
	scriptEngine        bool
	groovyShell         bool
	requestReceiver     bool
	objectInputStream   bool
	jndiContext         bool
	servletContext      bool
	constantString      string
	hasConstant         bool
	typedRequest        bool
	typedObjectInput    bool
	typedGroovyShell    bool
}

type javaAssignment struct {
	name         string
	rhs          string
	declaredType string
}

type assignmentFacts struct {
	tainted             bool
	executablePath      bool
	executableWriter    bool
	scriptEngineManager bool
	scriptEngine        bool
	groovyShell         bool
	requestReceiver     bool
	objectInputStream   bool
	jndiContext         bool
	servletContext      bool
	constantString      string
	hasConstant         bool
}

func newAnalyzerState(jsp bool) *analyzerState {
	state := &analyzerState{
		tainted:              map[string]bool{},
		executablePaths:      map[string]bool{},
		executableWriters:    map[string]bool{},
		scriptEngineManagers: map[string]bool{},
		scriptEngines:        map[string]bool{},
		groovyShells:         map[string]bool{},
		requestReceivers:     map[string]bool{},
		objectInputStreams:   map[string]bool{},
		jndiContexts:         map[string]bool{},
		servletContexts:      map[string]bool{},
		constantStrings:      map[string]string{},
		typedRequest:         map[string]bool{},
		typedObjectInput:     map[string]bool{},
		typedGroovyShell:     map[string]bool{},
		scopes:               []analyzerScope{{declarations: map[string]scopedNameFacts{}}},
		allowJSPPageContext:  jsp,
	}
	if jsp {
		state.requestReceivers["request"] = true
		state.servletContexts["servletcontext"] = true
	}
	return state
}

func (state *analyzerState) assign(name string, facts assignmentFacts) {
	delete(state.tainted, name)
	delete(state.executablePaths, name)
	delete(state.executableWriters, name)
	delete(state.scriptEngineManagers, name)
	delete(state.scriptEngines, name)
	delete(state.groovyShells, name)
	delete(state.requestReceivers, name)
	delete(state.objectInputStreams, name)
	delete(state.jndiContexts, name)
	delete(state.servletContexts, name)
	delete(state.constantStrings, name)

	if facts.tainted {
		state.tainted[name] = true
	}
	if facts.executablePath {
		state.executablePaths[name] = true
	}
	if facts.executableWriter {
		state.executableWriters[name] = true
	}
	if facts.scriptEngineManager {
		state.scriptEngineManagers[name] = true
	}
	if facts.scriptEngine {
		state.scriptEngines[name] = true
	}
	if facts.groovyShell || state.typedGroovyShell[name] {
		state.groovyShells[name] = true
	}
	if facts.requestReceiver || state.typedRequest[name] {
		state.requestReceivers[name] = true
	}
	if facts.objectInputStream || state.typedObjectInput[name] {
		state.objectInputStreams[name] = true
	}
	if facts.jndiContext {
		state.jndiContexts[name] = true
	}
	if facts.servletContext {
		state.servletContexts[name] = true
	}
	if facts.hasConstant {
		state.constantStrings[name] = facts.constantString
	}
}

func (state *analyzerState) pushScope() {
	state.scopes = append(state.scopes, analyzerScope{declarations: map[string]scopedNameFacts{}})
}

func (state *analyzerState) popScope() {
	if len(state.scopes) <= 1 {
		return
	}
	scope := state.scopes[len(state.scopes)-1]
	for name, facts := range scope.declarations {
		state.restoreName(name, facts)
	}
	state.scopes = state.scopes[:len(state.scopes)-1]
}

func (state *analyzerState) declare(name string) {
	scope := &state.scopes[len(state.scopes)-1]
	if _, exists := scope.declarations[name]; exists {
		return
	}
	scope.declarations[name] = state.nameFacts(name)
}

func (state *analyzerState) nameFacts(name string) scopedNameFacts {
	constant, hasConstant := state.constantStrings[name]
	return scopedNameFacts{
		tainted:             state.tainted[name],
		executablePath:      state.executablePaths[name],
		executableWriter:    state.executableWriters[name],
		scriptEngineManager: state.scriptEngineManagers[name],
		scriptEngine:        state.scriptEngines[name],
		groovyShell:         state.groovyShells[name],
		requestReceiver:     state.requestReceivers[name],
		objectInputStream:   state.objectInputStreams[name],
		jndiContext:         state.jndiContexts[name],
		servletContext:      state.servletContexts[name],
		constantString:      constant,
		hasConstant:         hasConstant,
		typedRequest:        state.typedRequest[name],
		typedObjectInput:    state.typedObjectInput[name],
		typedGroovyShell:    state.typedGroovyShell[name],
	}
}

func (state *analyzerState) restoreName(name string, facts scopedNameFacts) {
	delete(state.typedRequest, name)
	delete(state.typedObjectInput, name)
	delete(state.typedGroovyShell, name)
	state.assign(name, assignmentFacts{})

	if facts.tainted {
		state.tainted[name] = true
	}
	if facts.executablePath {
		state.executablePaths[name] = true
	}
	if facts.executableWriter {
		state.executableWriters[name] = true
	}
	if facts.scriptEngineManager {
		state.scriptEngineManagers[name] = true
	}
	if facts.scriptEngine {
		state.scriptEngines[name] = true
	}
	if facts.groovyShell {
		state.groovyShells[name] = true
	}
	if facts.requestReceiver {
		state.requestReceivers[name] = true
	}
	if facts.objectInputStream {
		state.objectInputStreams[name] = true
	}
	if facts.jndiContext {
		state.jndiContexts[name] = true
	}
	if facts.servletContext {
		state.servletContexts[name] = true
	}
	if facts.hasConstant {
		state.constantStrings[name] = facts.constantString
	}
	if facts.typedRequest {
		state.typedRequest[name] = true
	}
	if facts.typedObjectInput {
		state.typedObjectInput[name] = true
	}
	if facts.typedGroovyShell {
		state.typedGroovyShell[name] = true
	}
}

func (state *analyzerState) discoverTypedReceivers(statement string) {
	for _, match := range reTypedReceiverDeclaration.FindAllStringSubmatch(stripJavaStrings(statement), -1) {
		typeName, name := match[1], match[2]
		state.declare(name)
		switch typeName {
		case "httpservletrequest", "servletrequest":
			state.typedRequest[name] = true
			state.requestReceivers[name] = true
		case "objectinputstream":
			state.typedObjectInput[name] = true
			state.objectInputStreams[name] = true
		case "groovyshell":
			state.typedGroovyShell[name] = true
			state.groovyShells[name] = true
		}
	}
}

func parseAssignment(statement string) (javaAssignment, bool) {
	code := stripJavaStrings(statement)
	operator := simpleAssignmentOperator(code)
	if operator < 0 {
		return javaAssignment{}, false
	}

	lhs := strings.TrimSpace(code[:operator])
	if structural := strings.LastIndexAny(lhs, "{}("); structural >= 0 {
		lhs = strings.TrimSpace(lhs[structural+1:])
	}
	target := reTrailingIdentifier.FindStringIndex(lhs)
	if target == nil || target[1] != len(lhs) {
		return javaAssignment{}, false
	}
	name := strings.TrimSpace(lhs[target[0]:target[1]])
	declaredType := strings.TrimSpace(lhs[:target[0]])
	if strings.HasSuffix(declaredType, ".") || strings.ContainsAny(declaredType, "(){};=") {
		return javaAssignment{}, false
	}
	return javaAssignment{
		name:         name,
		rhs:          strings.TrimSpace(statement[operator+1:]),
		declaredType: declaredType,
	}, true
}

func simpleAssignmentOperator(code string) int {
	for i := 0; i < len(code); i++ {
		if code[i] != '=' {
			continue
		}
		if i+1 < len(code) && code[i+1] == '=' {
			continue
		}
		if i > 0 && strings.ContainsRune("=!<>+-*/%&|^", rune(code[i-1])) {
			continue
		}
		return i
	}
	return -1
}

func deriveAssignmentFacts(parsed javaAssignment, state *analyzerState) assignmentFacts {
	constant, hasConstant := constantStringValue(parsed.rhs, state.constantStrings)
	executablePath := containsExecutablePathLiteral(parsed.rhs) ||
		expressionIsReceiverAlias(parsed.rhs, state.executablePaths)
	if hasConstant {
		executablePath = containsExecutablePathMarker(constant)
	}
	return assignmentFacts{
		tainted:          inputControlled(parsed.rhs, state),
		executablePath:   executablePath,
		executableWriter: fileWriterTargetsExecutablePath(parsed.rhs, state.executablePaths),
		scriptEngineManager: declaredTypeContains(parsed.declaredType, "scriptenginemanager") ||
			expressionIsReceiverAlias(parsed.rhs, state.scriptEngineManagers) || hasScriptEngineManagerFactory(parsed.rhs),
		scriptEngine: declaredTypeContains(parsed.declaredType, "scriptengine") ||
			expressionIsReceiverAlias(parsed.rhs, state.scriptEngines) || hasScriptEngineFactory(parsed.rhs, state.scriptEngineManagers),
		groovyShell: declaredTypeContains(parsed.declaredType, "groovyshell") ||
			expressionIsReceiverAlias(parsed.rhs, state.groovyShells) || hasGroovyShellFactory(parsed.rhs),
		requestReceiver: declaredTypeContains(parsed.declaredType, "httpservletrequest", "servletrequest") ||
			expressionIsReceiverAlias(parsed.rhs, state.requestReceivers) ||
			(state.allowJSPPageContext && rePageContextRequest.MatchString(stripJavaStrings(parsed.rhs))),
		objectInputStream: declaredTypeContains(parsed.declaredType, "objectinputstream") ||
			expressionIsReceiverAlias(parsed.rhs, state.objectInputStreams) ||
			reNewObjectInputStream.MatchString(stripJavaStrings(parsed.rhs)),
		jndiContext: declaredTypeContains(parsed.declaredType, "initialcontext") ||
			expressionIsReceiverAlias(parsed.rhs, state.jndiContexts) ||
			reNewInitialContext.MatchString(stripJavaStrings(parsed.rhs)),
		servletContext: declaredTypeContains(parsed.declaredType, "servletcontext") ||
			expressionIsReceiverAlias(parsed.rhs, state.servletContexts) ||
			reGetServletContext.MatchString(stripJavaStrings(parsed.rhs)),
		constantString: constant,
		hasConstant:    hasConstant,
	}
}

func declaredTypeContains(declaredType string, types ...string) bool {
	for _, identifier := range reIdentifier.FindAllString(declaredType, -1) {
		for _, expected := range types {
			if identifier == expected {
				return true
			}
		}
	}
	return false
}

func expressionIsReceiverAlias(expression string, receivers map[string]bool) bool {
	code := strings.TrimSpace(stripJavaStrings(expression))
	for strings.HasPrefix(code, "(") {
		end := strings.IndexByte(code, ')')
		if end < 0 {
			return false
		}
		code = strings.TrimSpace(code[end+1:])
	}
	return reExactIdentifier.MatchString(code) && receivers[code]
}

func inputControlled(statement string, state *analyzerState) bool {
	code := stripJavaStrings(statement)
	if hasRequestSourceCall(code, state.requestReceivers) {
		return true
	}
	for _, identifier := range reIdentifier.FindAllString(code, -1) {
		if state.tainted[identifier] {
			return true
		}
	}
	return false
}

func hasRequestSourceCall(statement string, requestReceivers map[string]bool) bool {
	code := stripJavaStrings(statement)
	for _, match := range reReceiverCall.FindAllStringSubmatch(code, -1) {
		if requestReceivers[match[1]] && requestSourceMethods[match[2]] {
			return true
		}
	}
	return false
}

func hasExecSink(statement string) bool {
	return len(processExecutionArguments(statement)) != 0
}

func executionArgumentsContainReverseShell(statement string, constants map[string]string) bool {
	for _, args := range processExecutionArguments(statement) {
		if executionArgumentContainsReverseShell(args, constants) {
			return true
		}
	}
	return false
}

func processExecutionArgumentsInputControlled(statement string, state *analyzerState) bool {
	for _, args := range processExecutionArguments(statement) {
		if inputControlled(args, state) {
			return true
		}
	}
	return false
}

func processExecutionArguments(statement string) []string {
	return callArgumentsMatching(statement, reRuntimeExecCall, reProcessBuilderCall)
}

func executionArgumentContainsReverseShell(arguments string, constants map[string]string) bool {
	for _, literal := range javaStringLiterals(arguments) {
		if containsAny(literal, reverseShellLiterals) {
			return true
		}
	}
	for _, argument := range javaArguments(arguments) {
		identifier := strings.TrimSpace(stripJavaStrings(argument))
		if reExactIdentifier.MatchString(identifier) && containsAny(constants[identifier], reverseShellLiterals) {
			return true
		}
	}
	return false
}

func sinkArgumentsInputControlled(statement string, callPrefixes []string, state *analyzerState) bool {
	for _, prefix := range callPrefixes {
		for _, args := range callArguments(statement, prefix) {
			if inputControlled(args, state) {
				return true
			}
		}
	}
	return false
}

func callArguments(statement, prefix string) []string {
	var arguments []string
	code := stripJavaStrings(statement)
	for start := 0; ; {
		i := strings.Index(code[start:], prefix)
		if i < 0 {
			return arguments
		}
		i += start
		if !callPrefixBoundary(code, i, prefix) {
			start = i + 1
			continue
		}
		argumentsStart := i + len(prefix)
		if end := matchingParen(statement, argumentsStart); end >= 0 {
			arguments = append(arguments, statement[argumentsStart:end])
			start = end + 1
		} else {
			return arguments
		}
	}
}

func callArgumentsMatching(statement string, patterns ...*regexp.Regexp) []string {
	var arguments []string
	code := stripJavaStrings(statement)
	for _, pattern := range patterns {
		for _, match := range pattern.FindAllStringIndex(code, -1) {
			openParen := match[0] + strings.LastIndexByte(code[match[0]:match[1]], '(')
			if end := matchingParen(statement, openParen+1); end >= 0 {
				arguments = append(arguments, statement[openParen+1:end])
			}
		}
	}
	return arguments
}

func callPrefixBoundary(code string, start int, prefix string) bool {
	if start == 0 || prefix[0] == '.' {
		return true
	}
	previous := code[start-1]
	return !((previous >= 'a' && previous <= 'z') || (previous >= '0' && previous <= '9') || previous == '_' || previous == '$')
}

func matchingParen(s string, start int) int {
	depth := 1
	inString, inChar, escaped := false, false, false
	for i := start; i < len(s); i++ {
		c := s[i]
		if inString || inChar {
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if (inString && c == '"') || (inChar && c == '\'') {
				inString, inChar = false, false
			}
			continue
		}
		switch c {
		case '"':
			inString = true
		case '\'':
			inChar = true
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

type javaStatement struct {
	text     string
	boundary byte
}

func javaStatements(s string) []javaStatement {
	var statements []javaStatement
	start := 0
	parenDepth := 0
	inString, inChar, escaped := false, false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inString || inChar {
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if (inString && c == '"') || (inChar && c == '\'') {
				inString, inChar = false, false
			}
			continue
		}
		switch c {
		case '"':
			inString = true
		case '\'':
			inChar = true
		case '(':
			parenDepth++
		case ')':
			if parenDepth > 0 {
				parenDepth--
			}
		case ';':
			if parenDepth == 0 {
				statements = append(statements, javaStatement{text: s[start:i], boundary: c})
				start = i + 1
			}
		case '{', '}':
			if parenDepth == 0 {
				statements = append(statements, javaStatement{text: s[start:i], boundary: c})
				start = i + 1
			}
		}
	}
	return append(statements, javaStatement{text: s[start:]})
}

func fileWriteReceivesInput(statement string, state *analyzerState) bool {
	for _, args := range callArguments(statement, "files.write(") {
		arguments := javaArguments(args)
		if len(arguments) < 2 || !expressionHasExecutablePath(arguments[0], state.executablePaths) {
			continue
		}
		for _, data := range arguments[1:] {
			if inputControlled(data, state) {
				return true
			}
		}
	}
	if !sinkArgumentsInputControlled(statement, []string{".write("}, state) {
		return false
	}
	if hasWriterWrite(statement, state.executableWriters) {
		return true
	}
	return fileWriterTargetsExecutablePath(statement, state.executablePaths)
}

func fileWriterTargetsExecutablePath(statement string, executablePaths map[string]bool) bool {
	for _, prefix := range fileWriterConstructorPrefixes {
		for _, args := range callArguments(statement, prefix) {
			arguments := javaArguments(args)
			if len(arguments) != 0 && expressionHasExecutablePath(arguments[0], executablePaths) {
				return true
			}
		}
	}
	return false
}

func expressionHasExecutablePath(expression string, executablePaths map[string]bool) bool {
	return containsExecutablePathLiteral(expression) || expressionIsReceiverAlias(expression, executablePaths)
}

func containsExecutablePathLiteral(expression string) bool {
	for i := 0; i < len(expression); i++ {
		if expression[i] != '"' {
			continue
		}
		literal, end, ok := javaStringLiteralAt(expression, i)
		if !ok {
			return false
		}
		if containsExecutablePathMarker(literal) &&
			(literalTerminatesPathExpression(expression, end) || containsStableExecutableDirectory(literal)) {
			return true
		}
		i = end - 1
	}
	return false
}

func literalTerminatesPathExpression(expression string, start int) bool {
	for _, c := range expression[start:] {
		switch c {
		case ' ', '\t', '\r', '\n', ')', ']', '}':
			continue
		default:
			return false
		}
	}
	return true
}

func containsStableExecutableDirectory(path string) bool {
	path = strings.ReplaceAll(strings.ToLower(path), `\`, "/")
	for _, directory := range executablePathDirectories {
		for start := 0; ; {
			index := strings.Index(path[start:], directory)
			if index < 0 {
				break
			}
			index += start
			end := index + len(directory)
			if (index == 0 || path[index-1] == '/') && end < len(path) && path[end] == '/' {
				return true
			}
			start = index + 1
		}
	}
	return false
}

func containsExecutablePathMarker(path string) bool {
	path = strings.ReplaceAll(strings.ToLower(path), `\`, "/")
	for _, extension := range executablePathExtensions {
		if strings.HasSuffix(path, extension) {
			return true
		}
	}
	for _, directory := range executablePathDirectories {
		if containsPathDirectory(path, directory) {
			return true
		}
	}
	return false
}

func containsPathDirectory(path, directory string) bool {
	for start := 0; ; {
		index := strings.Index(path[start:], directory)
		if index < 0 {
			return false
		}
		index += start
		end := index + len(directory)
		beforeBoundary := index == 0 || path[index-1] == '/'
		afterBoundary := end == len(path) || path[end] == '/'
		if beforeBoundary && afterBoundary {
			return true
		}
		start = index + 1
	}
}

func constantStringValue(expression string, constants map[string]string) (string, bool) {
	expression = strings.TrimSpace(expression)
	if literal, end, ok := javaStringLiteralAt(expression, 0); ok && strings.TrimSpace(expression[end:]) == "" {
		return literal, true
	}
	code := strings.TrimSpace(stripJavaStrings(expression))
	if reExactIdentifier.MatchString(code) {
		constant, ok := constants[code]
		return constant, ok
	}
	return "", false
}

func javaStringLiterals(expression string) []string {
	var literals []string
	for i := 0; i < len(expression); i++ {
		if expression[i] != '"' {
			continue
		}
		literal, end, ok := javaStringLiteralAt(expression, i)
		if !ok {
			return literals
		}
		literals = append(literals, literal)
		i = end - 1
	}
	return literals
}

func javaStringLiteralAt(expression string, start int) (string, int, bool) {
	if start >= len(expression) || expression[start] != '"' {
		return "", start, false
	}
	escaped := false
	for i := start + 1; i < len(expression); i++ {
		if escaped {
			escaped = false
			continue
		}
		if expression[i] == '\\' {
			escaped = true
			continue
		}
		if expression[i] == '"' {
			return expression[start+1 : i], i + 1, true
		}
	}
	return "", len(expression), false
}

func javaArguments(arguments string) []string {
	var out []string
	start := 0
	parenDepth, bracketDepth, braceDepth := 0, 0, 0
	inString, inChar, escaped := false, false, false
	for i := 0; i < len(arguments); i++ {
		c := arguments[i]
		if inString || inChar {
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if (inString && c == '"') || (inChar && c == '\'') {
				inString, inChar = false, false
			}
			continue
		}
		switch c {
		case '"':
			inString = true
		case '\'':
			inChar = true
		case '(':
			parenDepth++
		case ')':
			parenDepth--
		case '[':
			bracketDepth++
		case ']':
			bracketDepth--
		case '{':
			braceDepth++
		case '}':
			braceDepth--
		case ',':
			if parenDepth == 0 && bracketDepth == 0 && braceDepth == 0 {
				out = append(out, strings.TrimSpace(arguments[start:i]))
				start = i + 1
			}
		}
	}
	return append(out, strings.TrimSpace(arguments[start:]))
}

func hasClassloadSink(statement string) bool {
	return strings.Contains(stripJavaStrings(statement), ".defineclass(")
}

func hasScriptEngineSink(statement string, scriptEngineManagers map[string]bool) bool {
	code := stripJavaStrings(statement)
	return strings.Contains(code, ".eval(") && hasScriptEngineFactory(code, scriptEngineManagers)
}

func hasScriptEngineManagerFactory(statement string) bool {
	return reNewScriptEngineManager.MatchString(stripJavaStrings(statement))
}

func hasScriptEngineFactory(statement string, scriptEngineManagers map[string]bool) bool {
	code := stripJavaStrings(statement)
	if !strings.Contains(code, ".getenginebyname(") {
		return false
	}
	return hasScriptEngineManagerFactory(code) || hasReceiverMethod(statement, "getenginebyname", scriptEngineManagers)
}

func hasScriptEngineEval(statement string, scriptEngines map[string]bool) bool {
	return hasReceiverMethod(statement, "eval", scriptEngines)
}

func hasGroovyShellFactory(statement string) bool {
	code := stripJavaStrings(statement)
	return containsAny(code, []string{"new groovyshell(", "new groovy.lang.groovyshell("})
}

func scriptEvaluationReceivesInput(statement string, state *analyzerState) bool {
	if hasScriptEngineSink(statement, state.scriptEngineManagers) &&
		firstArgumentInputControlled(callArguments(statement, ".eval("), state) {
		return true
	}
	if hasScriptEngineEval(statement, state.scriptEngines) &&
		firstArgumentInputControlled(receiverMethodArguments(statement, "eval", state.scriptEngines), state) {
		return true
	}
	if hasGroovyShellFactory(statement) &&
		firstArgumentInputControlled(callArguments(statement, ".evaluate("), state) {
		return true
	}
	if hasReceiverMethod(statement, "evaluate", state.groovyShells) &&
		firstArgumentInputControlled(receiverMethodArguments(statement, "evaluate", state.groovyShells), state) {
		return true
	}
	if firstArgumentInputControlled(callArguments(statement, "ognl.getvalue("), state) {
		return true
	}
	return firstArgumentInputControlled(callArguments(statement, "mvel.eval("), state)
}

func receiverMethodArguments(statement, method string, receivers map[string]bool) []string {
	var arguments []string
	code := stripJavaStrings(statement)
	for _, match := range reReceiverCall.FindAllStringSubmatchIndex(code, -1) {
		receiver := code[match[2]:match[3]]
		matchedMethod := code[match[4]:match[5]]
		if matchedMethod != method || !receivers[receiver] {
			continue
		}
		if end := matchingParen(statement, match[1]); end >= 0 {
			arguments = append(arguments, statement[match[1]:end])
		}
	}
	return arguments
}

func firstArgumentInputControlled(argumentLists []string, state *analyzerState) bool {
	for _, arguments := range argumentLists {
		parsed := javaArguments(arguments)
		if len(parsed) != 0 && inputControlled(parsed[0], state) {
			return true
		}
	}
	return false
}

func hasWriterWrite(statement string, executableWriters map[string]bool) bool {
	return hasReceiverMethod(statement, "write", executableWriters)
}

func hasReceiverMethod(statement, method string, receivers map[string]bool) bool {
	for _, match := range reReceiverCall.FindAllStringSubmatch(stripJavaStrings(statement), -1) {
		if receivers[match[1]] && match[2] == method {
			return true
		}
	}
	return false
}

func hasReflectionSink(statement string) bool {
	code := stripJavaStrings(statement)
	return strings.Contains(code, ".invoke(") && containsAny(code, []string{"class.forname", ".getmethod(", ".getdeclaredmethod("})
}

func isJavaOrJSPPath(path string) bool {
	return isJSPPath(path) || strings.HasSuffix(strings.ToLower(path), ".java")
}

func hasDeserializationContext(statement string, objectInputStreams map[string]bool) bool {
	code := stripJavaStrings(statement)
	if hasReceiverMethod(statement, "readobject", objectInputStreams) ||
		hasReceiverMethod(statement, "resolveclass", objectInputStreams) ||
		hasDirectObjectInputStreamCall(statement) {
		return true
	}
	return strings.Contains(code, "jdbcrowsetimpl") &&
		containsAny(code, []string{".setdatasourcename(", ".setautocommit(", ".execute("})
}

func hasDirectObjectInputStreamCall(statement string) bool {
	code := stripJavaStrings(statement)
	for _, match := range reNewObjectInputStream.FindAllStringIndex(code, -1) {
		end := matchingParen(statement, match[1])
		if end < 0 {
			continue
		}
		remainder := strings.TrimSpace(code[end+1:])
		if strings.HasPrefix(remainder, ".readobject(") || strings.HasPrefix(remainder, ".resolveclass(") {
			return true
		}
	}
	return false
}

func hasRemoteJNDILookup(statement string, jndiContexts map[string]bool) bool {
	code := stripJavaStrings(statement)
	for _, match := range reDirectInitialContextLookup.FindAllStringIndex(code, -1) {
		if end := matchingParen(statement, match[1]); end >= 0 && argumentsContainJNDIURL(statement[match[1]:end]) {
			return true
		}
	}
	for _, match := range reReceiverCall.FindAllStringSubmatchIndex(code, -1) {
		receiver := code[match[2]:match[3]]
		method := code[match[4]:match[5]]
		if method != "lookup" || !jndiContexts[receiver] {
			continue
		}
		if end := matchingParen(statement, match[1]); end >= 0 && argumentsContainJNDIURL(statement[match[1]:end]) {
			return true
		}
	}
	return false
}

func argumentsContainJNDIURL(arguments string) bool {
	for _, literal := range javaStringLiterals(arguments) {
		if containsAny(literal, []string{"ldap://", "rmi://"}) {
			return true
		}
	}
	return false
}

func hasServletHookRegistration(statement string, servletContexts map[string]bool) bool {
	for _, match := range reReceiverCall.FindAllStringSubmatch(stripJavaStrings(statement), -1) {
		if servletContexts[match[1]] && servletHookMethods[match[2]] {
			return true
		}
	}
	return false
}

func normalizeAnalyzerText(path string, data []byte) string {
	s := normalizeJSPText(path, data)
	s = reUniEscape.ReplaceAllStringFunc(s, func(escape string) string {
		n, err := strconv.ParseInt(escape[2:], 16, 32)
		if err != nil {
			return escape
		}
		return string(rune(n))
	})
	return reHexEscape.ReplaceAllStringFunc(s, func(escape string) string {
		n, err := strconv.ParseInt(escape[2:], 16, 8)
		if err != nil {
			return escape
		}
		return string(byte(n))
	})
}

func stripJavaStrings(s string) string {
	var out strings.Builder
	out.Grow(len(s))
	inString, inChar, escaped := false, false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inString || inChar {
			out.WriteByte(' ')
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if (inString && c == '"') || (inChar && c == '\'') {
				inString, inChar = false, false
			}
			continue
		}
		if c == '"' {
			inString = true
			out.WriteByte(' ')
			continue
		}
		if c == '\'' {
			inChar = true
			out.WriteByte(' ')
			continue
		}
		out.WriteByte(c)
	}
	return out.String()
}

func stripJavaComments(s string) string {
	var out strings.Builder
	out.Grow(len(s))
	inString, inChar, escaped := false, false, false

	for i := 0; i < len(s); i++ {
		c := s[i]
		if inString || inChar {
			out.WriteByte(c)
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if (inString && c == '"') || (inChar && c == '\'') {
				inString, inChar = false, false
			}
			continue
		}
		if c == '"' {
			inString = true
			out.WriteByte(c)
			continue
		}
		if c == '\'' {
			inChar = true
			out.WriteByte(c)
			continue
		}
		if c == '/' && i+1 < len(s) {
			switch s[i+1] {
			case '/':
				i++
				for i+1 < len(s) && s[i+1] != '\n' && s[i+1] != '\r' {
					i++
				}
				continue
			case '*':
				i++
				for i+1 < len(s) && !(s[i] == '*' && s[i+1] == '/') {
					i++
					if s[i] == '\n' || s[i] == '\r' {
						out.WriteByte(s[i])
					}
				}
				if i+1 < len(s) {
					i++
				}
				continue
			}
		}
		out.WriteByte(c)
	}
	return out.String()
}

func containsAny(s string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}
