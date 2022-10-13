FROM openjdk:8
ADD target/first-service.jar first-service.jar
EXPOSE 8081
ENTRYPOINT ["java", "-jar", "first-service.jar"]