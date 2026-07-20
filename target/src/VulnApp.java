import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.ParserConfig;
import com.sun.net.httpserver.HttpServer;

import java.io.*;
import java.net.*;

/**
 * Deliberately-vulnerable target for the fastjson @JSONType remote-class-load RCE.
 *
 * It binds a request body into a typed DTO with:
 *     JSON.parseObject(body, Dto.class)
 * i.e. autoType is NOT enabled and the parse is "type-bound" — the exact shape that
 * is commonly (wrongly) believed to be safe. The only special thing here is that
 * fastjson's default classloader is Spring Boot's LaunchedURLClassLoader, which is
 * present in EVERY Spring Boot fat jar. We instantiate it directly to keep the lab
 * dependency-light; a real Spring Boot fat jar on JDK 8 + fastjson 1.2.66-1.2.83 is
 * equivalently affected.
 *
 * See docs/MECHANISM.md and the references in README.md.
 */
public class VulnApp {
    public static class Dto {
        public int x;
        public int getX() { return x; }
        public void setX(int v) { x = v; }
    }

    public static void main(String[] args) throws Exception {
        int port = Integer.getInteger("app.port", 8080);
        File fjjar = new File(System.getProperty("app.fastjsonJar", "/app/lib/fastjson.jar"));

        // Reproduce the vulnerable condition: fastjson resolves the @JSONType probe
        // resource through a Spring Boot LaunchedURLClassLoader.
        org.springframework.boot.loader.jar.JarFile.registerUrlProtocolHandler();
        URL[] urls = {
            new URL("jar:" + fjjar.toURI().toURL() + "!/"),
            new File("/app/classes").toURI().toURL()
        };
        ClassLoader fatCL = new org.springframework.boot.loader.LaunchedURLClassLoader(
                urls, ClassLoader.getSystemClassLoader().getParent());
        ParserConfig.getGlobalInstance().setDefaultClassLoader(fatCL);

        HttpServer server = HttpServer.create(new InetSocketAddress("0.0.0.0", port), 0);
        server.createContext("/", ex -> {
            String resp;
            if ("/parse".equals(ex.getRequestURI().getPath())) {
                String body = new String(readAll(ex.getRequestBody()), "UTF-8");
                System.out.println("[target] parseObject(body, Dto.class)  body=" + body);
                try {
                    Dto d = JSON.parseObject(body, Dto.class);   // <-- the sink
                    resp = "{\"ok\":true,\"x\":" + d.x + "}";
                } catch (Throwable t) {
                    resp = "{\"ok\":false,\"error\":\"" + t.getClass().getSimpleName() + "\"}";
                }
            } else {
                resp = "fastjson @JSONType RCE lab target. POST JSON to /parse "
                     + "(bound to Dto.class, autoType OFF). fastjson=" + JSON.VERSION
                     + " classloader=" + ParserConfig.getGlobalInstance().getDefaultClassLoader().getClass().getName();
            }
            byte[] rb = resp.getBytes("UTF-8");
            ex.getResponseHeaders().set("Content-Type", "application/json");
            ex.sendResponseHeaders(200, rb.length);
            ex.getResponseBody().write(rb);
            ex.close();
        });
        server.setExecutor(null);
        server.start();
        System.out.println("[target] listening :" + port + "  fastjson=" + JSON.VERSION
                + "  autoType=" + ParserConfig.getGlobalInstance().isAutoTypeSupport()
                + "  classloader=" + fatCL.getClass().getName());
    }

    static byte[] readAll(InputStream in) throws IOException {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        byte[] b = new byte[4096]; int n;
        while ((n = in.read(b)) > 0) o.write(b, 0, n);
        return o.toByteArray();
    }
}
