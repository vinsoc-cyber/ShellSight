package com.shellsight.javamem;

import com.google.gson.*;
import com.google.gson.annotations.SerializedName;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

// Loads pipeline contracts and capability needles from mem-contracts.json at runtime.
// If the file is absent or malformed, the caller falls back to compiled-in defaults.
final class MemContracts {
    static final class JavaSection {
        @SerializedName("pipeline_contracts")   List<String> pipelineContracts   = new ArrayList<>();
        @SerializedName("type_needles")         List<String> typeNeedles         = new ArrayList<>();
        @SerializedName("string_needles")       List<String> stringNeedles       = new ArrayList<>();
        @SerializedName("retransform_watchlist") List<String> retransformWatchlist = new ArrayList<>();
    }
    @SerializedName("java") JavaSection java = new JavaSection();

    private static final Gson GSON = new Gson();

    static MemContracts tryLoad(Path p) {
        if (p == null || !Files.exists(p)) return new MemContracts();
        try {
            String json = new String(Files.readAllBytes(p), StandardCharsets.UTF_8);
            MemContracts mc = GSON.fromJson(json, MemContracts.class);
            if (mc == null) mc = new MemContracts();
            if (mc.java == null) mc.java = new JavaSection();
            return mc;
        } catch (Exception e) {
            System.err.println("javamem: mem-contracts: " + e.getMessage() + " — using compiled-in defaults");
            return new MemContracts();
        }
    }
}
