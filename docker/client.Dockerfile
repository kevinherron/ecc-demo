# syntax=docker/dockerfile:1

FROM maven:3-eclipse-temurin-25 AS build
WORKDIR /workspace

RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY scripts/bootstrap-milo.sh scripts/bootstrap-milo.sh
COPY vendor/milo vendor/milo
RUN --mount=type=cache,target=/root/.m2 \
    ./scripts/bootstrap-milo.sh

COPY gradle gradle
COPY gradlew gradlew
COPY settings.gradle.kts build.gradle.kts gradle.properties ./
COPY server/build.gradle.kts server/build.gradle.kts
COPY client/build.gradle.kts client/build.gradle.kts
COPY server/src server/src
COPY client/src client/src

RUN --mount=type=cache,target=/root/.m2 \
    --mount=type=cache,target=/root/.gradle \
    ./gradlew --no-daemon :client:shadowJar

FROM eclipse-temurin:25-jre
WORKDIR /opt/ecc-demo

RUN mkdir -p /data/client

VOLUME ["/data"]

COPY --from=build /workspace/client/build/libs/ecc-demo-client-*-all.jar /opt/ecc-demo/ecc-demo-client.jar

ENTRYPOINT ["java", "--enable-native-access=ALL-UNNAMED", "--sun-misc-unsafe-memory-access=allow", "-Dorg.slf4j.simpleLogger.defaultLogLevel=warn", "-jar", "/opt/ecc-demo/ecc-demo-client.jar"]
