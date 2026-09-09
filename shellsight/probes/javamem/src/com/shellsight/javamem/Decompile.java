package com.shellsight.javamem;

import org.benf.cfr.reader.api.*;
import java.io.IOException;
import java.nio.file.*;
import java.util.*;

// Recovered .class bytes -> Java source via CFR. Writes to a temp file (CFR analyses paths),
// captures the DECOMPILED sink.
final class Decompile {
    static String toJava(byte[] classBytes, String className) throws IOException {
        Path tmp = Files.createTempFile("javamem-dc-", ".class");
        Files.write(tmp, classBytes);
        try {
            StringBuilder out = new StringBuilder();
            OutputSinkFactory sink = new OutputSinkFactory() {
                public List<SinkClass> getSupportedSinks(SinkType type, Collection<SinkClass> available) {
                    return (type == SinkType.JAVA && available.contains(SinkClass.DECOMPILED))
                        ? Collections.singletonList(SinkClass.DECOMPILED) : Collections.singletonList(SinkClass.STRING);
                }
                @SuppressWarnings("unchecked")
                public <T> Sink<T> getSink(SinkType type, SinkClass sinkClass) {
                    if (type == SinkType.JAVA && sinkClass == SinkClass.DECOMPILED)
                        return (Sink<T>)(Sink<SinkReturns.Decompiled>) d -> out.append(d.getJava());
                    return ignored -> {};
                }
            };
            Map<String,String> opts = new HashMap<>(); opts.put("silent", "true");
            new CfrDriver.Builder().withOutputSink(sink).withOptions(opts).build().analyse(Collections.singletonList(tmp.toString()));
            return out.length() > 0 ? out.toString() : "// CFR produced no output for " + className;
        } finally { try { Files.deleteIfExists(tmp); } catch (IOException ignore) {} }
    }
}
