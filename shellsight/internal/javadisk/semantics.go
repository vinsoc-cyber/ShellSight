package javadisk

import "strings"

type methodFeatures struct {
	RequestSource    bool
	Exec             bool
	DynamicLoad      bool
	Decode           bool
	ScriptEval       bool
	HookRegistration bool
	Evidence         []string
}

type sinkKind uint8

const (
	sinkExec sinkKind = iota + 1
	sinkDynamicLoad
	sinkScriptEval
	sinkExecutableWrite
	sinkReflection
	sinkDeserializationJNDI
	sinkHookRegistration
)

type apiSignature struct {
	Owner      string
	Name       string
	Descriptor string
}

type apiCatalog map[apiSignature]struct{}

func api(owner, name, descriptor string) apiSignature {
	return apiSignature{Owner: owner, Name: name, Descriptor: descriptor}
}

func catalog(entries ...apiSignature) apiCatalog {
	result := make(apiCatalog, len(entries))
	for _, entry := range entries {
		result[entry] = struct{}{}
	}
	return result
}

func (c apiCatalog) matches(reference memberReference) bool {
	_, ok := c[api(reference.Owner, reference.Name, reference.Descriptor)]
	return ok
}

var requestSourceAPIs = catalog(
	// javax.servlet request data.
	api("javax/servlet/ServletRequest", "getParameter", "(Ljava/lang/String;)Ljava/lang/String;"),
	api("javax/servlet/ServletRequest", "getParameterMap", "()Ljava/util/Map;"),
	api("javax/servlet/ServletRequest", "getParameterValues", "(Ljava/lang/String;)[Ljava/lang/String;"),
	api("javax/servlet/ServletRequest", "getInputStream", "()Ljavax/servlet/ServletInputStream;"),
	api("javax/servlet/ServletRequest", "getReader", "()Ljava/io/BufferedReader;"),
	api("javax/servlet/http/HttpServletRequest", "getParameter", "(Ljava/lang/String;)Ljava/lang/String;"),
	api("javax/servlet/http/HttpServletRequest", "getParameterMap", "()Ljava/util/Map;"),
	api("javax/servlet/http/HttpServletRequest", "getParameterValues", "(Ljava/lang/String;)[Ljava/lang/String;"),
	api("javax/servlet/http/HttpServletRequest", "getHeader", "(Ljava/lang/String;)Ljava/lang/String;"),
	api("javax/servlet/http/HttpServletRequest", "getHeaders", "(Ljava/lang/String;)Ljava/util/Enumeration;"),
	api("javax/servlet/http/HttpServletRequest", "getCookies", "()[Ljavax/servlet/http/Cookie;"),
	api("javax/servlet/http/HttpServletRequest", "getInputStream", "()Ljavax/servlet/ServletInputStream;"),
	api("javax/servlet/http/HttpServletRequest", "getReader", "()Ljava/io/BufferedReader;"),

	// jakarta.servlet request data.
	api("jakarta/servlet/ServletRequest", "getParameter", "(Ljava/lang/String;)Ljava/lang/String;"),
	api("jakarta/servlet/ServletRequest", "getParameterMap", "()Ljava/util/Map;"),
	api("jakarta/servlet/ServletRequest", "getParameterValues", "(Ljava/lang/String;)[Ljava/lang/String;"),
	api("jakarta/servlet/ServletRequest", "getInputStream", "()Ljakarta/servlet/ServletInputStream;"),
	api("jakarta/servlet/ServletRequest", "getReader", "()Ljava/io/BufferedReader;"),
	api("jakarta/servlet/http/HttpServletRequest", "getParameter", "(Ljava/lang/String;)Ljava/lang/String;"),
	api("jakarta/servlet/http/HttpServletRequest", "getParameterMap", "()Ljava/util/Map;"),
	api("jakarta/servlet/http/HttpServletRequest", "getParameterValues", "(Ljava/lang/String;)[Ljava/lang/String;"),
	api("jakarta/servlet/http/HttpServletRequest", "getHeader", "(Ljava/lang/String;)Ljava/lang/String;"),
	api("jakarta/servlet/http/HttpServletRequest", "getHeaders", "(Ljava/lang/String;)Ljava/util/Enumeration;"),
	api("jakarta/servlet/http/HttpServletRequest", "getCookies", "()[Ljakarta/servlet/http/Cookie;"),
	api("jakarta/servlet/http/HttpServletRequest", "getInputStream", "()Ljakarta/servlet/ServletInputStream;"),
	api("jakarta/servlet/http/HttpServletRequest", "getReader", "()Ljava/io/BufferedReader;"),
)

var pageContextRequestAPIs = catalog(
	api("javax/servlet/jsp/PageContext", "getRequest", "()Ljavax/servlet/ServletRequest;"),
	api("jakarta/servlet/jsp/PageContext", "getRequest", "()Ljakarta/servlet/ServletRequest;"),
)

var sessionAttributeSourceAPIs = catalog(
	api("javax/servlet/http/HttpSession", "getAttribute", "(Ljava/lang/String;)Ljava/lang/Object;"),
	api("jakarta/servlet/http/HttpSession", "getAttribute", "(Ljava/lang/String;)Ljava/lang/Object;"),
)

var applicationAttributeSourceAPIs = catalog(
	api("javax/servlet/ServletContext", "getAttribute", "(Ljava/lang/String;)Ljava/lang/Object;"),
	api("jakarta/servlet/ServletContext", "getAttribute", "(Ljava/lang/String;)Ljava/lang/Object;"),
)

var runtimeExecAPIs = catalog(
	api("java/lang/Runtime", "exec", "(Ljava/lang/String;)Ljava/lang/Process;"),
	api("java/lang/Runtime", "exec", "([Ljava/lang/String;)Ljava/lang/Process;"),
	api("java/lang/Runtime", "exec", "(Ljava/lang/String;[Ljava/lang/String;)Ljava/lang/Process;"),
	api("java/lang/Runtime", "exec", "([Ljava/lang/String;[Ljava/lang/String;)Ljava/lang/Process;"),
	api("java/lang/Runtime", "exec", "(Ljava/lang/String;[Ljava/lang/String;Ljava/io/File;)Ljava/lang/Process;"),
	api("java/lang/Runtime", "exec", "([Ljava/lang/String;[Ljava/lang/String;Ljava/io/File;)Ljava/lang/Process;"),
)

var processBuilderConstructorAPIs = catalog(
	api("java/lang/ProcessBuilder", "<init>", "([Ljava/lang/String;)V"),
	api("java/lang/ProcessBuilder", "<init>", "(Ljava/util/List;)V"),
)

var processBuilderStartAPIs = catalog(
	api("java/lang/ProcessBuilder", "start", "()Ljava/lang/Process;"),
)

var base64DecodeAPIs = catalog(
	api("java/util/Base64$Decoder", "decode", "([B)[B"),
	api("java/util/Base64$Decoder", "decode", "(Ljava/lang/String;)[B"),
	api("java/util/Base64$Decoder", "decode", "([B[B)I"),
	api("java/util/Base64$Decoder", "decode", "(Ljava/nio/ByteBuffer;)Ljava/nio/ByteBuffer;"),
	api("javax/xml/bind/DatatypeConverter", "parseBase64Binary", "(Ljava/lang/String;)[B"),
)

var hexDecodeAPIs = catalog(
	api("javax/xml/bind/DatatypeConverter", "parseHexBinary", "(Ljava/lang/String;)[B"),
	api("org/apache/commons/codec/binary/Hex", "decodeHex", "([C)[B"),
	api("org/apache/commons/codec/binary/Hex", "decodeHex", "(Ljava/lang/String;)[B"),
)

var urlDecodeAPIs = catalog(
	api("java/net/URLDecoder", "decode", "(Ljava/lang/String;)Ljava/lang/String;"),
	api("java/net/URLDecoder", "decode", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;"),
	api("java/net/URLDecoder", "decode", "(Ljava/lang/String;Ljava/nio/charset/Charset;)Ljava/lang/String;"),
)

var stringTransformAPIs = catalog(
	api("java/lang/String", "concat", "(Ljava/lang/String;)Ljava/lang/String;"),
	api("java/lang/String", "valueOf", "(Ljava/lang/Object;)Ljava/lang/String;"),
	api("java/lang/String", "valueOf", "([C)Ljava/lang/String;"),
	api("java/lang/String", "copyValueOf", "([C)Ljava/lang/String;"),
	api("java/lang/String", "getBytes", "()[B"),
	api("java/lang/String", "getBytes", "(Ljava/lang/String;)[B"),
	api("java/lang/String", "getBytes", "(Ljava/nio/charset/Charset;)[B"),
)

var pathTransformAPIs = catalog(
	api("java/nio/file/Paths", "get", "(Ljava/lang/String;[Ljava/lang/String;)Ljava/nio/file/Path;"),
	api("java/nio/file/Path", "of", "(Ljava/lang/String;[Ljava/lang/String;)Ljava/nio/file/Path;"),
)

var executableWriteAPIs = catalog(
	api("java/nio/file/Files", "write", "(Ljava/nio/file/Path;[B[Ljava/nio/file/OpenOption;)Ljava/nio/file/Path;"),
	api("java/nio/file/Files", "writeString", "(Ljava/nio/file/Path;Ljava/lang/CharSequence;[Ljava/nio/file/OpenOption;)Ljava/nio/file/Path;"),
	api("java/nio/file/Files", "newOutputStream", "(Ljava/nio/file/Path;[Ljava/nio/file/OpenOption;)Ljava/io/OutputStream;"),
)

var reflectionExecutionAPIs = catalog(
	api("java/lang/reflect/Method", "invoke", "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;"),
	api("java/lang/reflect/Constructor", "newInstance", "([Ljava/lang/Object;)Ljava/lang/Object;"),
	api("java/lang/Class", "newInstance", "()Ljava/lang/Object;"),
)

var jndiLookupAPIs = catalog(
	api("javax/naming/Context", "lookup", "(Ljava/lang/String;)Ljava/lang/Object;"),
	api("javax/naming/InitialContext", "lookup", "(Ljava/lang/String;)Ljava/lang/Object;"),
	api("javax/naming/directory/DirContext", "lookup", "(Ljava/lang/String;)Ljava/lang/Object;"),
	api("javax/naming/Context", "lookupLink", "(Ljava/lang/String;)Ljava/lang/Object;"),
	api("javax/naming/InitialContext", "lookupLink", "(Ljava/lang/String;)Ljava/lang/Object;"),
)

var deserializationAPIs = catalog(
	api("java/io/ObjectInputStream", "readObject", "()Ljava/lang/Object;"),
	api("java/io/ObjectInputStream", "readUnshared", "()Ljava/lang/Object;"),
	api("java/beans/XMLDecoder", "readObject", "()Ljava/lang/Object;"),
)

var responseAccessAPIs = catalog(
	api("javax/servlet/ServletResponse", "getWriter", "()Ljava/io/PrintWriter;"),
	api("javax/servlet/ServletResponse", "getOutputStream", "()Ljavax/servlet/ServletOutputStream;"),
	api("javax/servlet/http/HttpServletResponse", "getWriter", "()Ljava/io/PrintWriter;"),
	api("javax/servlet/http/HttpServletResponse", "getOutputStream", "()Ljavax/servlet/ServletOutputStream;"),
	api("jakarta/servlet/ServletResponse", "getWriter", "()Ljava/io/PrintWriter;"),
	api("jakarta/servlet/ServletResponse", "getOutputStream", "()Ljakarta/servlet/ServletOutputStream;"),
	api("jakarta/servlet/http/HttpServletResponse", "getWriter", "()Ljava/io/PrintWriter;"),
	api("jakarta/servlet/http/HttpServletResponse", "getOutputStream", "()Ljakarta/servlet/ServletOutputStream;"),
)

var classDefinitionAPIs = catalog(
	// ClassLoader and SecureClassLoader protected definition entry points.
	api("java/lang/ClassLoader", "defineClass", "([BII)Ljava/lang/Class;"),
	api("java/lang/ClassLoader", "defineClass", "(Ljava/lang/String;[BII)Ljava/lang/Class;"),
	api("java/lang/ClassLoader", "defineClass", "(Ljava/lang/String;[BIILjava/security/ProtectionDomain;)Ljava/lang/Class;"),
	api("java/lang/ClassLoader", "defineClass", "(Ljava/lang/String;Ljava/nio/ByteBuffer;Ljava/security/ProtectionDomain;)Ljava/lang/Class;"),
	api("java/security/SecureClassLoader", "defineClass", "(Ljava/lang/String;[BIILjava/security/CodeSource;)Ljava/lang/Class;"),
	api("java/security/SecureClassLoader", "defineClass", "(Ljava/lang/String;Ljava/nio/ByteBuffer;Ljava/security/CodeSource;)Ljava/lang/Class;"),

	// Supported MethodHandles and JDK Unsafe class-definition APIs.
	api("java/lang/invoke/MethodHandles$Lookup", "defineClass", "([B)Ljava/lang/Class;"),
	api("java/lang/invoke/MethodHandles$Lookup", "defineHiddenClass", "([BZ[Ljava/lang/invoke/MethodHandles$Lookup$ClassOption;)Ljava/lang/invoke/MethodHandles$Lookup;"),
	api("java/lang/invoke/MethodHandles$Lookup", "defineHiddenClassWithClassData", "([BLjava/lang/Object;Z[Ljava/lang/invoke/MethodHandles$Lookup$ClassOption;)Ljava/lang/invoke/MethodHandles$Lookup;"),
	api("sun/misc/Unsafe", "defineClass", "(Ljava/lang/String;[BIILjava/lang/ClassLoader;Ljava/security/ProtectionDomain;)Ljava/lang/Class;"),
	api("sun/misc/Unsafe", "defineAnonymousClass", "(Ljava/lang/Class;[B[Ljava/lang/Object;)Ljava/lang/Class;"),
	api("jdk/internal/misc/Unsafe", "defineClass", "(Ljava/lang/String;[BIILjava/lang/ClassLoader;Ljava/security/ProtectionDomain;)Ljava/lang/Class;"),
)

var classLoaderDefinitionDescriptors = map[string]struct{}{
	"([BII)Ljava/lang/Class;":                                                                    {},
	"(Ljava/lang/String;[BII)Ljava/lang/Class;":                                                  {},
	"(Ljava/lang/String;[BIILjava/security/ProtectionDomain;)Ljava/lang/Class;":                  {},
	"(Ljava/lang/String;Ljava/nio/ByteBuffer;Ljava/security/ProtectionDomain;)Ljava/lang/Class;": {},
}

var secureClassLoaderDefinitionDescriptors = map[string]struct{}{
	"(Ljava/lang/String;[BIILjava/security/CodeSource;)Ljava/lang/Class;":                  {},
	"(Ljava/lang/String;Ljava/nio/ByteBuffer;Ljava/security/CodeSource;)Ljava/lang/Class;": {},
}

var scriptEvaluationAPIs = catalog(
	// javax.script evaluation and compilation.
	api("javax/script/ScriptEngine", "eval", "(Ljava/lang/String;)Ljava/lang/Object;"),
	api("javax/script/ScriptEngine", "eval", "(Ljava/io/Reader;)Ljava/lang/Object;"),
	api("javax/script/ScriptEngine", "eval", "(Ljava/lang/String;Ljavax/script/ScriptContext;)Ljava/lang/Object;"),
	api("javax/script/ScriptEngine", "eval", "(Ljava/io/Reader;Ljavax/script/ScriptContext;)Ljava/lang/Object;"),
	api("javax/script/ScriptEngine", "eval", "(Ljava/lang/String;Ljavax/script/Bindings;)Ljava/lang/Object;"),
	api("javax/script/ScriptEngine", "eval", "(Ljava/io/Reader;Ljavax/script/Bindings;)Ljava/lang/Object;"),
	api("javax/script/Compilable", "compile", "(Ljava/lang/String;)Ljavax/script/CompiledScript;"),
	api("javax/script/Compilable", "compile", "(Ljava/io/Reader;)Ljavax/script/CompiledScript;"),

	// Groovy shell, classloader, and shorthand evaluation.
	api("groovy/lang/GroovyShell", "evaluate", "(Ljava/lang/String;)Ljava/lang/Object;"),
	api("groovy/lang/GroovyShell", "evaluate", "(Ljava/io/File;)Ljava/lang/Object;"),
	api("groovy/lang/GroovyShell", "evaluate", "(Ljava/net/URI;)Ljava/lang/Object;"),
	api("groovy/lang/GroovyShell", "evaluate", "(Ljava/io/Reader;)Ljava/lang/Object;"),
	api("groovy/lang/GroovyShell", "evaluate", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/Object;"),
	api("groovy/lang/GroovyShell", "evaluate", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/Object;"),
	api("groovy/lang/GroovyShell", "evaluate", "(Ljava/io/Reader;Ljava/lang/String;)Ljava/lang/Object;"),
	api("groovy/lang/GroovyShell", "evaluate", "(Ljava/io/Reader;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/Object;"),
	api("groovy/lang/GroovyShell", "parse", "(Ljava/lang/String;)Lgroovy/lang/Script;"),
	api("groovy/lang/GroovyShell", "parse", "(Ljava/io/Reader;)Lgroovy/lang/Script;"),
	api("groovy/lang/GroovyClassLoader", "parseClass", "(Ljava/io/File;)Ljava/lang/Class;"),
	api("groovy/lang/GroovyClassLoader", "parseClass", "(Ljava/lang/String;)Ljava/lang/Class;"),
	api("groovy/lang/GroovyClassLoader", "parseClass", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/Class;"),
	api("groovy/lang/GroovyClassLoader", "parseClass", "(Ljava/io/Reader;Ljava/lang/String;)Ljava/lang/Class;"),
	api("groovy/lang/GroovyClassLoader", "parseClass", "(Lgroovy/lang/GroovyCodeSource;)Ljava/lang/Class;"),
	api("groovy/lang/GroovyClassLoader", "parseClass", "(Lgroovy/lang/GroovyCodeSource;Z)Ljava/lang/Class;"),
	api("groovy/util/Eval", "me", "(Ljava/lang/String;)Ljava/lang/Object;"),
	api("groovy/util/Eval", "me", "(Ljava/lang/String;Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;"),
	api("groovy/util/Eval", "x", "(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;"),
	api("groovy/util/Eval", "xy", "(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;"),
	api("groovy/util/Eval", "xyz", "(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;"),

	// OGNL expression evaluation.
	api("ognl/Ognl", "getValue", "(Ljava/lang/Object;Ljava/util/Map;Ljava/lang/Object;)Ljava/lang/Object;"),
	api("ognl/Ognl", "getValue", "(Ljava/lang/String;Ljava/util/Map;Ljava/lang/Object;)Ljava/lang/Object;"),
	api("ognl/Ognl", "getValue", "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;"),
	api("ognl/Ognl", "getValue", "(Ljava/lang/String;Ljava/lang/Object;)Ljava/lang/Object;"),
	api("ognl/Ognl", "getValue", "(Ljava/lang/Object;Ljava/util/Map;Ljava/lang/Object;Ljava/lang/Class;)Ljava/lang/Object;"),
	api("ognl/Ognl", "getValue", "(Ljava/lang/String;Ljava/util/Map;Ljava/lang/Object;Ljava/lang/Class;)Ljava/lang/Object;"),
	api("ognl/Ognl", "setValue", "(Ljava/lang/Object;Ljava/util/Map;Ljava/lang/Object;Ljava/lang/Object;)V"),
	api("ognl/Ognl", "setValue", "(Ljava/lang/String;Ljava/util/Map;Ljava/lang/Object;Ljava/lang/Object;)V"),
	api("ognl/Ognl", "getValue", "(Ljava/lang/Object;Lognl/OgnlContext;Ljava/lang/Object;)Ljava/lang/Object;"),
	api("ognl/Ognl", "getValue", "(Ljava/lang/String;Lognl/OgnlContext;Ljava/lang/Object;)Ljava/lang/Object;"),
	api("ognl/Ognl", "getValue", "(Ljava/lang/Object;Lognl/OgnlContext;Ljava/lang/Object;Ljava/lang/Class;)Ljava/lang/Object;"),
	api("ognl/Ognl", "getValue", "(Ljava/lang/String;Lognl/OgnlContext;Ljava/lang/Object;Ljava/lang/Class;)Ljava/lang/Object;"),
	api("ognl/Ognl", "setValue", "(Ljava/lang/Object;Lognl/OgnlContext;Ljava/lang/Object;Ljava/lang/Object;)V"),
	api("ognl/Ognl", "setValue", "(Ljava/lang/String;Lognl/OgnlContext;Ljava/lang/Object;Ljava/lang/Object;)V"),

	// MVEL 2 and legacy package evaluation entry points.
	api("org/mvel2/MVEL", "eval", "(Ljava/lang/String;)Ljava/lang/Object;"),
	api("org/mvel2/MVEL", "eval", "(Ljava/lang/String;Ljava/lang/Object;)Ljava/lang/Object;"),
	api("org/mvel2/MVEL", "eval", "(Ljava/lang/String;Ljava/util/Map;)Ljava/lang/Object;"),
	api("org/mvel2/MVEL", "eval", "(Ljava/lang/String;Ljava/lang/Object;Ljava/util/Map;)Ljava/lang/Object;"),
	api("org/mvel2/MVEL", "eval", "(Ljava/lang/String;Ljava/lang/Class;)Ljava/lang/Object;"),
	api("org/mvel2/MVEL", "eval", "(Ljava/lang/String;Ljava/lang/Object;Ljava/lang/Class;)Ljava/lang/Object;"),
	api("org/mvel2/MVEL", "eval", "(Ljava/lang/String;Ljava/util/Map;Ljava/lang/Class;)Ljava/lang/Object;"),
	api("org/mvel2/MVEL", "eval", "(Ljava/lang/String;Ljava/lang/Object;Ljava/util/Map;Ljava/lang/Class;)Ljava/lang/Object;"),
	api("org/mvel2/MVEL", "executeExpression", "(Ljava/lang/Object;)Ljava/lang/Object;"),
	api("org/mvel2/MVEL", "executeExpression", "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;"),
	api("org/mvel2/MVEL", "executeExpression", "(Ljava/lang/Object;Ljava/util/Map;)Ljava/lang/Object;"),
	api("org/mvel2/MVEL", "executeExpression", "(Ljava/lang/Object;Ljava/lang/Object;Ljava/util/Map;)Ljava/lang/Object;"),
	api("org/mvel/MVEL", "eval", "(Ljava/lang/String;)Ljava/lang/Object;"),
	api("org/mvel/MVEL", "eval", "(Ljava/lang/String;Ljava/lang/Object;)Ljava/lang/Object;"),
)

var hookRegistrationAPIs = catalog(
	// Servlet, filter, and listener dynamic registration (javax).
	api("javax/servlet/ServletContext", "addServlet", "(Ljava/lang/String;Ljava/lang/String;)Ljavax/servlet/ServletRegistration$Dynamic;"),
	api("javax/servlet/ServletContext", "addServlet", "(Ljava/lang/String;Ljavax/servlet/Servlet;)Ljavax/servlet/ServletRegistration$Dynamic;"),
	api("javax/servlet/ServletContext", "addServlet", "(Ljava/lang/String;Ljava/lang/Class;)Ljavax/servlet/ServletRegistration$Dynamic;"),
	api("javax/servlet/ServletContext", "addFilter", "(Ljava/lang/String;Ljava/lang/String;)Ljavax/servlet/FilterRegistration$Dynamic;"),
	api("javax/servlet/ServletContext", "addFilter", "(Ljava/lang/String;Ljavax/servlet/Filter;)Ljavax/servlet/FilterRegistration$Dynamic;"),
	api("javax/servlet/ServletContext", "addFilter", "(Ljava/lang/String;Ljava/lang/Class;)Ljavax/servlet/FilterRegistration$Dynamic;"),
	api("javax/servlet/ServletContext", "addListener", "(Ljava/lang/String;)V"),
	api("javax/servlet/ServletContext", "addListener", "(Ljava/util/EventListener;)V"),
	api("javax/servlet/ServletContext", "addListener", "(Ljava/lang/Class;)V"),
	api("javax/servlet/ServletContext", "addJspFile", "(Ljava/lang/String;Ljava/lang/String;)Ljavax/servlet/ServletRegistration$Dynamic;"),
	api("javax/servlet/ServletRegistration$Dynamic", "addMapping", "([Ljava/lang/String;)Ljava/util/Set;"),
	api("javax/servlet/FilterRegistration$Dynamic", "addMappingForServletNames", "(Ljava/util/EnumSet;Z[Ljava/lang/String;)V"),
	api("javax/servlet/FilterRegistration$Dynamic", "addMappingForUrlPatterns", "(Ljava/util/EnumSet;Z[Ljava/lang/String;)V"),

	// Servlet, filter, and listener dynamic registration (jakarta).
	api("jakarta/servlet/ServletContext", "addServlet", "(Ljava/lang/String;Ljava/lang/String;)Ljakarta/servlet/ServletRegistration$Dynamic;"),
	api("jakarta/servlet/ServletContext", "addServlet", "(Ljava/lang/String;Ljakarta/servlet/Servlet;)Ljakarta/servlet/ServletRegistration$Dynamic;"),
	api("jakarta/servlet/ServletContext", "addServlet", "(Ljava/lang/String;Ljava/lang/Class;)Ljakarta/servlet/ServletRegistration$Dynamic;"),
	api("jakarta/servlet/ServletContext", "addFilter", "(Ljava/lang/String;Ljava/lang/String;)Ljakarta/servlet/FilterRegistration$Dynamic;"),
	api("jakarta/servlet/ServletContext", "addFilter", "(Ljava/lang/String;Ljakarta/servlet/Filter;)Ljakarta/servlet/FilterRegistration$Dynamic;"),
	api("jakarta/servlet/ServletContext", "addFilter", "(Ljava/lang/String;Ljava/lang/Class;)Ljakarta/servlet/FilterRegistration$Dynamic;"),
	api("jakarta/servlet/ServletContext", "addListener", "(Ljava/lang/String;)V"),
	api("jakarta/servlet/ServletContext", "addListener", "(Ljava/util/EventListener;)V"),
	api("jakarta/servlet/ServletContext", "addListener", "(Ljava/lang/Class;)V"),
	api("jakarta/servlet/ServletContext", "addJspFile", "(Ljava/lang/String;Ljava/lang/String;)Ljakarta/servlet/ServletRegistration$Dynamic;"),
	api("jakarta/servlet/ServletRegistration$Dynamic", "addMapping", "([Ljava/lang/String;)Ljava/util/Set;"),
	api("jakarta/servlet/FilterRegistration$Dynamic", "addMappingForServletNames", "(Ljava/util/EnumSet;Z[Ljava/lang/String;)V"),
	api("jakarta/servlet/FilterRegistration$Dynamic", "addMappingForUrlPatterns", "(Ljava/util/EnumSet;Z[Ljava/lang/String;)V"),

	// WebSocket endpoints.
	api("javax/websocket/server/ServerContainer", "addEndpoint", "(Ljava/lang/Class;)V"),
	api("javax/websocket/server/ServerContainer", "addEndpoint", "(Ljavax/websocket/server/ServerEndpointConfig;)V"),
	api("jakarta/websocket/server/ServerContainer", "addEndpoint", "(Ljava/lang/Class;)V"),
	api("jakarta/websocket/server/ServerContainer", "addEndpoint", "(Ljakarta/websocket/server/ServerEndpointConfig;)V"),

	// Tomcat context, filter-map, servlet-map, listener, and valve mutation.
	api("org/apache/catalina/core/StandardContext", "addFilterDef", "(Lorg/apache/tomcat/util/descriptor/web/FilterDef;)V"),
	api("org/apache/catalina/core/StandardContext", "addFilterMap", "(Lorg/apache/tomcat/util/descriptor/web/FilterMap;)V"),
	api("org/apache/catalina/core/StandardContext", "addFilterMapBefore", "(Lorg/apache/tomcat/util/descriptor/web/FilterMap;)V"),
	api("org/apache/catalina/core/StandardContext", "addApplicationEventListener", "(Ljava/lang/Object;)V"),
	api("org/apache/catalina/core/StandardContext", "addApplicationLifecycleListener", "(Ljava/lang/Object;)V"),
	api("org/apache/catalina/core/StandardContext", "addServletMappingDecoded", "(Ljava/lang/String;Ljava/lang/String;)V"),
	api("org/apache/catalina/core/StandardContext", "addServletMappingDecoded", "(Ljava/lang/String;Ljava/lang/String;Z)V"),
	api("org/apache/catalina/core/StandardContext", "addChild", "(Lorg/apache/catalina/Container;)V"),
	api("org/apache/catalina/Context", "addApplicationEventListener", "(Ljava/lang/Object;)V"),
	api("org/apache/catalina/Context", "addServletMappingDecoded", "(Ljava/lang/String;Ljava/lang/String;)V"),
	api("org/apache/catalina/Context", "addServletMappingDecoded", "(Ljava/lang/String;Ljava/lang/String;Z)V"),
	api("org/apache/catalina/Pipeline", "addValve", "(Lorg/apache/catalina/Valve;)V"),
	api("org/apache/catalina/core/StandardPipeline", "addValve", "(Lorg/apache/catalina/Valve;)V"),

	// Spring MVC/WebFlux handler mappings and interceptor registries.
	api("org/springframework/web/servlet/mvc/method/annotation/RequestMappingHandlerMapping", "registerMapping", "(Lorg/springframework/web/servlet/mvc/method/RequestMappingInfo;Ljava/lang/Object;Ljava/lang/reflect/Method;)V"),
	api("org/springframework/web/reactive/result/method/annotation/RequestMappingHandlerMapping", "registerMapping", "(Lorg/springframework/web/reactive/result/method/RequestMappingInfo;Ljava/lang/Object;Ljava/lang/reflect/Method;)V"),
	api("org/springframework/web/servlet/handler/AbstractHandlerMethodMapping", "registerMapping", "(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/reflect/Method;)V"),
	api("org/springframework/web/reactive/result/method/AbstractHandlerMethodMapping", "registerMapping", "(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/reflect/Method;)V"),
	api("org/springframework/web/servlet/handler/AbstractUrlHandlerMapping", "registerHandler", "(Ljava/lang/String;Ljava/lang/Object;)V"),
	api("org/springframework/web/servlet/config/annotation/InterceptorRegistry", "addInterceptor", "(Lorg/springframework/web/servlet/HandlerInterceptor;)Lorg/springframework/web/servlet/config/annotation/InterceptorRegistration;"),
	api("org/springframework/web/servlet/handler/AbstractHandlerMapping", "setInterceptors", "([Ljava/lang/Object;)V"),
)

var serverAnnotationDescriptors = map[string]struct{}{
	"Ljavax/servlet/annotation/WebServlet;":                    {},
	"Ljavax/servlet/annotation/WebFilter;":                     {},
	"Ljavax/servlet/annotation/WebListener;":                   {},
	"Ljakarta/servlet/annotation/WebServlet;":                  {},
	"Ljakarta/servlet/annotation/WebFilter;":                   {},
	"Ljakarta/servlet/annotation/WebListener;":                 {},
	"Ljavax/websocket/server/ServerEndpoint;":                  {},
	"Ljakarta/websocket/server/ServerEndpoint;":                {},
	"Lorg/springframework/stereotype/Controller;":              {},
	"Lorg/springframework/web/bind/annotation/RestController;": {},
	"Lorg/springframework/web/bind/annotation/RequestMapping;": {},
	"Lorg/springframework/web/bind/annotation/GetMapping;":     {},
	"Lorg/springframework/web/bind/annotation/PostMapping;":    {},
	"Lorg/springframework/web/bind/annotation/PutMapping;":     {},
	"Lorg/springframework/web/bind/annotation/DeleteMapping;":  {},
	"Lorg/springframework/web/bind/annotation/PatchMapping;":   {},
}

var serverHierarchyTypes = map[string]struct{}{
	"javax/servlet/Servlet":                              {},
	"javax/servlet/Filter":                               {},
	"javax/servlet/ServletContextListener":               {},
	"javax/servlet/ServletRequestListener":               {},
	"javax/servlet/http/HttpServlet":                     {},
	"javax/servlet/http/HttpSessionListener":             {},
	"jakarta/servlet/Servlet":                            {},
	"jakarta/servlet/Filter":                             {},
	"jakarta/servlet/ServletContextListener":             {},
	"jakarta/servlet/ServletRequestListener":             {},
	"jakarta/servlet/http/HttpServlet":                   {},
	"jakarta/servlet/http/HttpSessionListener":           {},
	"javax/websocket/Endpoint":                           {},
	"jakarta/websocket/Endpoint":                         {},
	"org/apache/catalina/Valve":                          {},
	"org/springframework/web/servlet/mvc/Controller":     {},
	"org/springframework/web/servlet/HandlerInterceptor": {},
}

func semanticFeatures(reference memberReference) methodFeatures {
	features := methodFeatures{}
	features.RequestSource = requestSourceAPIs.matches(reference)
	features.Exec = runtimeExecAPIs.matches(reference)
	features.Decode = base64DecodeAPIs.matches(reference)
	features.DynamicLoad = classDefinitionAPIs.matches(reference)
	features.ScriptEval = scriptEvaluationAPIs.matches(reference)
	features.HookRegistration = hookRegistrationAPIs.matches(reference)
	return features
}

func isInheritedClassDefinition(class *classModel, reference memberReference) bool {
	if class == nil || reference.Owner != class.Name || reference.Name != "defineClass" {
		return false
	}
	if _, ok := classLoaderDefinitionDescriptors[reference.Descriptor]; ok {
		switch class.Super {
		case "java/lang/ClassLoader", "java/security/SecureClassLoader", "java/net/URLClassLoader":
			return true
		}
	}
	if _, ok := secureClassLoaderDefinitionDescriptors[reference.Descriptor]; ok {
		return class.Super == "java/security/SecureClassLoader" || class.Super == "java/net/URLClassLoader"
	}
	return false
}

func isBuilderAppend(reference memberReference) bool {
	if reference.Owner != "java/lang/StringBuilder" && reference.Owner != "java/lang/StringBuffer" || reference.Name != "append" {
		return false
	}
	return builderAppendDescriptors(reference.Owner)[reference.Descriptor]
}

func builderAppendDescriptors(owner string) map[string]bool {
	return map[string]bool{
		"(Z)L" + owner + ";":                          true,
		"(C)L" + owner + ";":                          true,
		"(I)L" + owner + ";":                          true,
		"(J)L" + owner + ";":                          true,
		"(F)L" + owner + ";":                          true,
		"(D)L" + owner + ";":                          true,
		"(Ljava/lang/Object;)L" + owner + ";":         true,
		"(Ljava/lang/String;)L" + owner + ";":         true,
		"(Ljava/lang/StringBuffer;)L" + owner + ";":   true,
		"(Ljava/lang/CharSequence;)L" + owner + ";":   true,
		"([C)L" + owner + ";":                         true,
		"([CII)L" + owner + ";":                       true,
		"(Ljava/lang/CharSequence;II)L" + owner + ";": true,
	}
}

func isBuilderResult(reference memberReference) bool {
	return (reference.Owner == "java/lang/StringBuilder" || reference.Owner == "java/lang/StringBuffer") &&
		reference.Name == "toString" && reference.Descriptor == "()Ljava/lang/String;"
}

func isStreamWrite(reference memberReference) bool {
	switch reference.Owner {
	case "java/io/ByteArrayOutputStream", "java/io/OutputStream", "java/io/FileOutputStream",
		"javax/servlet/ServletOutputStream", "jakarta/servlet/ServletOutputStream":
		return (reference.Name == "write" && (reference.Descriptor == "([B)V" || reference.Descriptor == "([BII)V" || reference.Descriptor == "(I)V")) ||
			(reference.Name == "writeBytes" && reference.Descriptor == "([B)V")
	case "java/io/CharArrayWriter", "java/io/StringWriter", "java/io/Writer", "java/io/FileWriter",
		"java/io/BufferedWriter", "java/io/OutputStreamWriter":
		return reference.Name == "write" && (reference.Descriptor == "(Ljava/lang/String;)V" ||
			reference.Descriptor == "([C)V" || reference.Descriptor == "([CII)V" || reference.Descriptor == "(I)V")
	case "java/io/PrintWriter":
		if reference.Name == "write" {
			return reference.Descriptor == "(Ljava/lang/String;)V" || reference.Descriptor == "([C)V" ||
				reference.Descriptor == "([CII)V" || reference.Descriptor == "(I)V"
		}
		return (reference.Name == "print" || reference.Name == "println") &&
			(reference.Descriptor == "(Ljava/lang/String;)V" || reference.Descriptor == "(Ljava/lang/Object;)V" ||
				reference.Descriptor == "([C)V" || reference.Descriptor == "(C)V" || reference.Descriptor == "(Z)V" ||
				reference.Descriptor == "(I)V" || reference.Descriptor == "(J)V" || reference.Descriptor == "(F)V" ||
				reference.Descriptor == "(D)V")
	default:
		return false
	}
}

func isStreamResult(reference memberReference) bool {
	if reference.Name == "toByteArray" && reference.Descriptor == "()[B" {
		return reference.Owner == "java/io/ByteArrayOutputStream"
	}
	if reference.Name == "readAllBytes" && reference.Descriptor == "()[B" {
		return reference.Owner == "java/io/ByteArrayInputStream"
	}
	if reference.Name == "toCharArray" && reference.Descriptor == "()[C" {
		return reference.Owner == "java/io/CharArrayWriter"
	}
	if reference.Name == "readLine" && reference.Descriptor == "()Ljava/lang/String;" {
		return reference.Owner == "java/io/BufferedReader"
	}
	return reference.Name == "toString" && reference.Descriptor == "()Ljava/lang/String;" &&
		(reference.Owner == "java/io/ByteArrayOutputStream" || reference.Owner == "java/io/CharArrayWriter" || reference.Owner == "java/io/StringWriter")
}

func isCollectionMutation(reference memberReference) bool {
	switch reference.Owner {
	case "java/util/List":
		return reference.Name == "add" &&
			(reference.Descriptor == "(Ljava/lang/Object;)Z" || reference.Descriptor == "(ILjava/lang/Object;)V")
	case "java/util/Map":
		return reference.Name == "put" && reference.Descriptor == "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;"
	default:
		return false
	}
}

func isCollectionRead(reference memberReference) bool {
	switch reference.Owner {
	case "java/util/List":
		return reference.Name == "get" && reference.Descriptor == "(I)Ljava/lang/Object;"
	case "java/util/Map":
		return reference.Name == "get" && reference.Descriptor == "(Ljava/lang/Object;)Ljava/lang/Object;"
	default:
		return false
	}
}

func isCompressionTransform(reference memberReference) bool {
	if reference.Name == "readAllBytes" && reference.Descriptor == "()[B" ||
		reference.Name == "read" && (reference.Descriptor == "()I" || reference.Descriptor == "([B)I" || reference.Descriptor == "([BII)I") {
		switch reference.Owner {
		case "java/util/zip/GZIPInputStream", "java/util/zip/InflaterInputStream", "java/util/zip/ZipInputStream":
			return true
		}
	}
	return false
}

func isModeledConstructor(reference memberReference) bool {
	if reference.Name != "<init>" {
		return false
	}
	switch reference.Owner {
	case "java/lang/String":
		return reference.Descriptor == "()V" || reference.Descriptor == "(Ljava/lang/String;)V" ||
			reference.Descriptor == "([B)V" || reference.Descriptor == "([BLjava/lang/String;)V" || reference.Descriptor == "([C)V"
	case "java/lang/StringBuilder", "java/lang/StringBuffer":
		return reference.Descriptor == "()V" || reference.Descriptor == "(I)V" || reference.Descriptor == "(Ljava/lang/String;)V" ||
			reference.Descriptor == "(Ljava/lang/CharSequence;)V"
	case "java/io/ByteArrayInputStream":
		return reference.Descriptor == "([B)V" || reference.Descriptor == "([BII)V"
	case "java/io/ByteArrayOutputStream", "java/io/CharArrayWriter", "java/io/StringWriter":
		return reference.Descriptor == "()V" || reference.Descriptor == "(I)V"
	case "java/io/CharArrayReader":
		return reference.Descriptor == "([C)V" || reference.Descriptor == "([CII)V"
	case "java/io/StringReader":
		return reference.Descriptor == "(Ljava/lang/String;)V"
	case "java/io/InputStreamReader":
		return reference.Descriptor == "(Ljava/io/InputStream;)V" || reference.Descriptor == "(Ljava/io/InputStream;Ljava/lang/String;)V" ||
			reference.Descriptor == "(Ljava/io/InputStream;Ljava/nio/charset/Charset;)V"
	case "java/io/OutputStreamWriter":
		return reference.Descriptor == "(Ljava/io/OutputStream;)V" || reference.Descriptor == "(Ljava/io/OutputStream;Ljava/lang/String;)V" ||
			reference.Descriptor == "(Ljava/io/OutputStream;Ljava/nio/charset/Charset;)V"
	case "java/io/BufferedReader":
		return reference.Descriptor == "(Ljava/io/Reader;)V" || reference.Descriptor == "(Ljava/io/Reader;I)V"
	case "java/io/BufferedWriter":
		return reference.Descriptor == "(Ljava/io/Writer;)V" || reference.Descriptor == "(Ljava/io/Writer;I)V"
	case "java/io/ObjectInputStream":
		return reference.Descriptor == "(Ljava/io/InputStream;)V"
	case "java/beans/XMLDecoder":
		return reference.Descriptor == "(Ljava/io/InputStream;)V"
	case "java/util/zip/GZIPInputStream":
		return reference.Descriptor == "(Ljava/io/InputStream;)V" || reference.Descriptor == "(Ljava/io/InputStream;I)V"
	case "java/util/zip/InflaterInputStream":
		return reference.Descriptor == "(Ljava/io/InputStream;)V" || reference.Descriptor == "(Ljava/io/InputStream;Ljava/util/zip/Inflater;)V" ||
			reference.Descriptor == "(Ljava/io/InputStream;Ljava/util/zip/Inflater;I)V"
	case "java/io/FileOutputStream":
		return reference.Descriptor == "(Ljava/lang/String;)V" || reference.Descriptor == "(Ljava/lang/String;Z)V" ||
			reference.Descriptor == "(Ljava/io/File;)V" || reference.Descriptor == "(Ljava/io/File;Z)V"
	case "java/io/FileWriter":
		return reference.Descriptor == "(Ljava/lang/String;)V" || reference.Descriptor == "(Ljava/lang/String;Z)V" ||
			reference.Descriptor == "(Ljava/io/File;)V" || reference.Descriptor == "(Ljava/io/File;Z)V"
	default:
		return false
	}
}

func isModeledTransform(reference memberReference) bool {
	return stringTransformAPIs.matches(reference) || base64DecodeAPIs.matches(reference) || hexDecodeAPIs.matches(reference) ||
		urlDecodeAPIs.matches(reference) || pathTransformAPIs.matches(reference) || isBuilderAppend(reference) ||
		isBuilderResult(reference) || isStreamWrite(reference) || isStreamResult(reference) ||
		isCollectionMutation(reference) || isCollectionRead(reference) || isCompressionTransform(reference) ||
		isModeledConstructor(reference)
}

func isModeledSink(class *classModel, reference memberReference) bool {
	return runtimeExecAPIs.matches(reference) || processBuilderStartAPIs.matches(reference) ||
		classDefinitionAPIs.matches(reference) || isInheritedClassDefinition(class, reference) ||
		scriptEvaluationAPIs.matches(reference) || executableWriteAPIs.matches(reference) ||
		reflectionExecutionAPIs.matches(reference) || jndiLookupAPIs.matches(reference) ||
		deserializationAPIs.matches(reference) || hookRegistrationAPIs.matches(reference)
}

func isRemoteJNDI(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	return strings.HasPrefix(value, "ldap://") || strings.HasPrefix(value, "ldaps://") ||
		strings.HasPrefix(value, "rmi://")
}
