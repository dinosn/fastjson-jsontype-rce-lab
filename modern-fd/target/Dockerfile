FROM maven:3.9.6-eclipse-temurin-17@sha256:29a1658b1f3078e07c2b17f7b519b45eb47f65d9628e887eac45a8c5c8f939d4 AS builder
WORKDIR /build
COPY pom.xml ./
COPY src/ ./src/
RUN mvn -q -DskipTests package

FROM eclipse-temurin:17.0.19_10-jre-jammy@sha256:475d8e96b4b2bfe08999e5e854755c773af1581acdf959a4545d88f0696a2339
WORKDIR /app
COPY --from=builder --chown=65532:65532 /build/target/modern-fd-target-1.0.0.jar /app/app.jar
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
