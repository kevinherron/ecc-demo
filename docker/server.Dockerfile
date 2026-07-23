# syntax=docker/dockerfile:1

FROM eclipse-temurin:25-jdk AS build
WORKDIR /workspace

COPY gradle gradle
COPY gradlew gradlew
COPY settings.gradle.kts build.gradle.kts gradle.properties ./
COPY server/build.gradle.kts server/build.gradle.kts
COPY client/build.gradle.kts client/build.gradle.kts
COPY server/src server/src
COPY client/src client/src

RUN --mount=type=cache,target=/root/.gradle,sharing=locked \
    ./gradlew --no-daemon :server:shadowJar

FROM eclipse-temurin:25-jre
WORKDIR /opt/ecc-demo

RUN mkdir -p /data/server

VOLUME ["/data"]
EXPOSE 4840/tcp

COPY --from=build /workspace/server/build/libs/ecc-demo-server-*-all.jar /opt/ecc-demo/ecc-demo-server.jar

ENTRYPOINT ["java", "--enable-native-access=ALL-UNNAMED", "--sun-misc-unsafe-memory-access=allow", "-Dorg.slf4j.simpleLogger.defaultLogLevel=warn", "-jar", "/opt/ecc-demo/ecc-demo-server.jar"]
