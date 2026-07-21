FROM maven:3.9.6-eclipse-temurin-17@sha256:29a1658b1f3078e07c2b17f7b519b45eb47f65d9628e887eac45a8c5c8f939d4 AS builder
WORKDIR /build
COPY pom.xml ./
COPY src/ ./src/
RUN mvn -q -DskipTests package \
    && mkdir -p /out \
    && java -cp "target/classes:$HOME/.m2/repository/org/ow2/asm/asm/9.6/asm-9.6.jar" \
       lab.modernfd.artifact.MarkerJarBuilder /out/x

FROM python:3.12.4-alpine3.20@sha256:63094abdaf49e046da9f6529ecd6ce4d853d9bfbf00a25c52bbbb68b3223b490
WORKDIR /srv
COPY --from=builder --chown=65532:65532 /out/x /srv/x
USER 65532:65532
EXPOSE 18081
ENTRYPOINT ["python3", "-u", "-m", "http.server", "18081", "--bind", "0.0.0.0", "--directory", "/srv"]
