package com.shellsight.javamem;

import com.google.gson.*;
import com.google.gson.annotations.SerializedName;
import java.util.List;
import java.util.Map;

class TargetSpec {
    @SerializedName("host") String host = "";
    @SerializedName("pids") int[] pids;
    @SerializedName("webroots") String[] webroots;
    @SerializedName("dump_path") String dumpPath = "";
}
class Finding {
    @SerializedName("schema_version") String schemaVersion = "1.0";
    @SerializedName("id") String id = "";
    @SerializedName("host") String host = "";
    @SerializedName("view") String view = "java-mem";
    @SerializedName("target") Target target = new Target();
    @SerializedName("artifact") Artifact artifact = new Artifact();
    @SerializedName("detection") Detection detection = new Detection();
    @SerializedName("score") int score;
    @SerializedName("tier") String tier = "suspicious";
    @SerializedName("classification") Classification classification = new Classification();
    @SerializedName("artifacts") Artifacts artifacts = new Artifacts();
    @SerializedName("context") Map<String,String> context;
}
class Target { @SerializedName("kind") String kind = "process"; @SerializedName("process") ProcessRef process; @SerializedName("file") FileRef file; }
class ProcessRef { @SerializedName("pid") int pid; @SerializedName("name") String name = ""; }
class FileRef { @SerializedName("path") String path = ""; @SerializedName("sha256") String sha256 = ""; }
class Artifact { @SerializedName("kind") String kind = ""; @SerializedName("identity") String identity = ""; @SerializedName("location") String location = ""; }
class Detection { @SerializedName("basis") String basis = "structural-heuristic"; @SerializedName("knowledge_ref") String knowledgeRef = ""; @SerializedName("evidence") String evidence = ""; @SerializedName("allowlisted") boolean allowlisted; }
class Classification { @SerializedName("family") String family; @SerializedName("capability") String[] capability; @SerializedName("source") String source; @SerializedName("confidence") double confidence; }
class Artifacts { @SerializedName("raw") String raw = ""; @SerializedName("decompiled") String decompiled = ""; @SerializedName("features") String features = ""; }

final class Contract {
    // serializeNulls so classification.family/source/capability emit as JSON null (Go requires the key
    // present — the architected classifier hook). Go's encoding/json maps null -> zero value, safe to parse.
    private static final Gson GSON = new GsonBuilder().serializeNulls().disableHtmlEscaping().create();
    static String serialize(List<Finding> findings) { return GSON.toJson(findings); }

    /**
     * Probe coverage, mirroring Go's finding.ProbeCoverage. Field names are the JSON contract, so
     * they are spelled the way the core reads them.
     */
    static final class ProbeCoverage {
        String status;                 // ran | degraded | failed | n/a
        String reason;
        int targets_scanned;
        /**
         * The unbounded-gap flag. The core turns this into `incomplete`, which turns a clean tier
         * into `unknown` and exit 5, because a sweep that stopped early cannot say what was in the
         * part it never reached.
         *
         * <p>A primitive, so it always emits explicitly. GSON here is built with serializeNulls()
         * for the classification hook, which applies to the whole tree -- a boxed Boolean left null
         * emits as `truncated: null`, not as an absent key, so boxing bought nothing but ambiguity.
         * Go reads either into false; an explicit false is what a reader can act on.
         */
        boolean truncated;
    }

    /** The object form of the probe contract: {findings, coverage}. */
    static final class ProbeOutput {
        List<Finding> findings;
        ProbeCoverage coverage;
    }

    /**
     * Serialize the OBJECT form.
     *
     * <p>The probe used to print a bare findings array -- the legacy form the core still accepts --
     * which had no place to put a coverage statement, so budget exhaustion could not be reported
     * however much the probe knew about it. GSON is configured with serializeNulls for the
     * classification hook, so `truncated` is dropped explicitly rather than emitted as null.
     */
    static String serializeOutput(List<Finding> findings, ProbeCoverage coverage) {
        ProbeOutput out = new ProbeOutput();
        out.findings = findings;
        out.coverage = coverage;
        return GSON.toJson(out);
    }
    static TargetSpec parseSpec(String json) {
        if (json == null || json.isBlank()) return new TargetSpec();
        TargetSpec s = GSON.fromJson(json, TargetSpec.class);
        return s != null ? s : new TargetSpec();
    }
}
