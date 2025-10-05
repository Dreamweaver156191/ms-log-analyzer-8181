package za.co.frei.logfile.analyzer.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
public class OpenApiConfig {

    @Value("${project.name:Log File Analyzer}")
    private String projectName;

    @Value("${project.version:0.0.1-SNAPSHOT}")
    private String projectVersion;

    @Value("${project.description:Parses log files and analyzes user activity}")
    private String projectDescription;

    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title(projectName + " API")
                        .version(projectVersion)
                        .description(projectDescription + "\n\n" +
                                "This API provides endpoints for:\n" +
                                "- Uploading and parsing log files from multiple systems\n" +
                                "- Analyzing login patterns (success/failure counts per user)\n" +
                                "- Identifying top file uploaders\n" +
                                "- Detecting suspicious login activity (brute force attempts)\n" +
                                "- Exporting analysis results to JSON")
                        .contact(new Contact()
                                .name("Francois van der Merwe")
                                .email("francois156191@gmail.com"))
                        .license(new License()
                                .name("MIT License")
                                .url("https://opensource.org/licenses/MIT")))
                .servers(List.of(
                        new Server()
                                .url("http://localhost:8181")
                                .description("Local Development Server"),
                        new Server()
                                .url("https://api.example.com")  // Update after deployment
                                .description("Production Server")
                ));
    }
}