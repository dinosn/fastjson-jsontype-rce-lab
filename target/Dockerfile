# Target: JDK 8 + fastjson 1.2.83, parsing untrusted JSON with autoType OFF via a
# Spring Boot LaunchedURLClassLoader. JDK 8 => full RCE; switch the base image to a
# JDK 9+ tag to observe the SSRF-only downgrade.
FROM eclipse-temurin:8-jdk
WORKDIR /app
ADD https://repo1.maven.org/maven2/com/alibaba/fastjson/1.2.83/fastjson-1.2.83.jar /app/lib/fastjson.jar
ADD https://repo1.maven.org/maven2/org/springframework/boot/spring-boot-loader/2.7.18/spring-boot-loader-2.7.18.jar /app/lib/spring-boot-loader.jar
COPY src/ /app/src/
RUN mkdir -p /app/classes && javac -XDignore.symbol.file -cp "/app/lib/*" -d /app/classes /app/src/*.java
EXPOSE 8080
CMD ["sh","-c","java -cp /app/lib/*:/app/classes -Dapp.port=8080 -Dapp.fastjsonJar=/app/lib/fastjson.jar VulnApp"]
