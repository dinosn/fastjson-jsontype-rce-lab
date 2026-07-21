package lab.modernfd;

import com.alibaba.fastjson.parser.ParserConfig;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class ModernFdApplication {
    public static void main(String[] args) {
        ParserConfig config = ParserConfig.getGlobalInstance();
        if (config.isAutoTypeSupport()) {
            throw new IllegalStateException("lab requires Fastjson AutoType=false");
        }
        if (Boolean.getBoolean("lab.safeMode")) {
            config.setSafeMode(true);
        }
        SpringApplication.run(ModernFdApplication.class, args);
    }
}
