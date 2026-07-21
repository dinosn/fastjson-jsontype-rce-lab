package lab.modernfd;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.ParserConfig;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public final class ParseController {
    private static final String MARKER_KEY = "FASTJSON_MODERN_FD_MARKER";

    @GetMapping(value = "/health", produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> health() {
        return runtimeFacts();
    }

    @PostMapping(value = "/parse", consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> parse(@RequestBody String body) {
        Map<String, Object> result = runtimeFacts();
        result.put("bodyBytes", body.getBytes(java.nio.charset.StandardCharsets.UTF_8).length);
        try {
            // This exact fixed-DTO binding is the security claim under test.
            final BoundEnvelope parsed = JSON.parseObject(body, BoundEnvelope.class);
            result.put("ok", true);
            result.put("parsedClass", parsed == null ? null : parsed.getClass().getName());
            result.put("valueSize", parsed == null || parsed.getValue() == null
                    ? null : parsed.getValue().size());
        } catch (Throwable failure) {
            result.put("ok", false);
            result.put("errorClass", failure.getClass().getName());
            result.put("errorMessage", failure.getMessage());
        }
        result.put("marker", System.getProperty(MARKER_KEY));
        result.put("jarCacheFds", jarCacheDescriptors());
        System.out.println("PARSE_RESULT=" + JSON.toJSONString(result));
        return result;
    }

    private static Map<String, Object> runtimeFacts() {
        ParserConfig config = ParserConfig.getGlobalInstance();
        Map<String, Object> facts = new LinkedHashMap<>();
        facts.put("fastjson", JSON.VERSION);
        facts.put("java", System.getProperty("java.runtime.version"));
        facts.put("autoType", config.isAutoTypeSupport());
        facts.put("safeMode", config.isSafeMode());
        facts.put("parserLoader", loaderName(ParserConfig.class.getClassLoader()));
        facts.put("dtoLoader", loaderName(BoundEnvelope.class.getClassLoader()));
        facts.put("contextLoader", loaderName(Thread.currentThread().getContextClassLoader()));
        facts.put("configuredDefaultLoader", loaderName(config.getDefaultClassLoader()));
        facts.put("marker", System.getProperty(MARKER_KEY));
        return facts;
    }

    private static String loaderName(ClassLoader loader) {
        return loader == null ? null : loader.getClass().getName();
    }

    private static List<String> jarCacheDescriptors() {
        List<String> matches = new ArrayList<>();
        Path fdRoot = Path.of("/proc/self/fd");
        if (!Files.isDirectory(fdRoot)) {
            return matches;
        }
        try (var entries = Files.list(fdRoot)) {
            entries.sorted().forEach(entry -> {
                try {
                    String target = Files.readSymbolicLink(entry).toString();
                    if (target.contains("jar_cache")) {
                        matches.add(entry.getFileName() + "->" + target);
                    }
                } catch (IOException ignored) {
                    // Descriptors can disappear while the snapshot is taken.
                }
            });
        } catch (IOException ignored) {
            // Evidence is best-effort; parse behavior remains authoritative.
        }
        return matches;
    }
}
