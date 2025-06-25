FROM eclipse-temurin:17.0.10_7-jre-jammy

ENV TZ=Europe/Tallinn

EXPOSE 8443

ARG JAR_FILE=target/*.jar
COPY ${JAR_FILE} timur.jar
USER www-data

ENTRYPOINT ["java", "-jar", "timur.jar", "--spring.config.additional-location=file:/timur-config/"]
