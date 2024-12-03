import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.Scanner;

// Asset class representing entries in a CMDB
class Asset {
    String ipAddress;
    String name;
    String criticality;

    public Asset(String ipAddress, String name, String criticality) {
        this.ipAddress = ipAddress;
        this.name = name;
        this.criticality = criticality;
    }
}

public class VulnerabilityAPIIntegration {
    public static void main(String[] args) {
        // Mock CMDB data
        List<Asset> cmdb = Arrays.asList(
            new Asset("192.168.1.10", "Web Server 1", "High"),
            new Asset("192.168.1.11", "Database Server", "Critical"),
            new Asset("192.168.1.12", "Backup Server", "Medium")
        );

        try {
            // Fetch vulnerability data from the API
            String apiUrl = "https://mock-vulnerability-scanner/api/vulnerabilities";
            String jsonResponse = fetchVulnerabilitiesFromAPI(apiUrl);

            // Parse and process vulnerability data
            ObjectMapper objectMapper = new ObjectMapper();
            JsonNode vulnerabilities = objectMapper.readTree(jsonResponse);

            for (JsonNode vuln : vulnerabilities) {
                String ipAddress = vuln.get("ip_address").asText();
                String vulnId = vuln.get("vulnerability_id").asText();
                int severity = vuln.get("severity").asInt();

                // Match vulnerabilities to CMDB assets
                Optional<Asset> matchingAsset = cmdb.stream()
                        .filter(asset -> asset.ipAddress.equals(ipAddress))
                        .findFirst();

                if (matchingAsset.isPresent()) {
                    Asset asset = matchingAsset.get();
                    System.out.println("Vulnerability Found:");
                    System.out.println(" - Asset: " + asset.name + " (" + asset.criticality + ")");
                    System.out.println(" - Vulnerability ID: " + vulnId);
                    System.out.println(" - Severity: " + severity);
                    System.out.println(" - Priority: " + calculatePriority(asset.criticality, severity));
                    System.out.println();
                } else {
                    System.out.println("Vulnerability " + vulnId + " found on unknown asset (IP: " + ipAddress + ").");
                }
            }
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            log.error(" handling exception {} ", errorMessage);
        }
    }

    // Fetch vulnerabilities from API
    private static String fetchVulnerabilitiesFromAPI(String apiUrl) throws IOException {
        URL url = new URL(apiUrl);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        conn.setRequestProperty("Accept", "application/json");

        if (conn.getResponseCode() != 200) {
            throw new RuntimeException("Failed to connect to API: HTTP error code " + conn.getResponseCode());
        }

        // Read the response
        Scanner scanner = new Scanner(conn.getInputStream());
        StringBuilder response = new StringBuilder();
        while (scanner.hasNext()) {
            response.append(scanner.nextLine());
        }
        scanner.close();
        conn.disconnect();

        return response.toString();
    }

    // Calculate remediation priority based on criticality and severity
    private static String calculatePriority(String criticality, int severity) {
        if (criticality.equals("Critical") && severity >= 4) {
            return "High";
        } else if (criticality
