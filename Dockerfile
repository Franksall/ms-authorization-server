FROM eclipse-temurin:17-jdk-alpine
RUN apk add --no-cache curl
WORKDIR /app

COPY build/libs/*.jar app.jar

EXPOSE 9000

ENTRYPOINT ["java", "-jar", "/app/app.jar"]