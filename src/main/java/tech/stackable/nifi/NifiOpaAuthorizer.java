package tech.stackable.nifi;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.nifi.authorization.*;
import org.apache.nifi.authorization.exception.AuthorizationAccessException;
import org.apache.nifi.authorization.exception.AuthorizerCreationException;
import org.apache.nifi.authorization.exception.AuthorizerDestructionException;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;

public class NifiOpaAuthorizer implements Authorizer {
    public static final String GROUPURIENVNAME = "NIFI_OPA_URI";
    private final HttpClient httpClient = HttpClient.newHttpClient();
    private final ObjectMapper json = new ObjectMapper();
    private final URI defaultOpaGroupUri = URI.create("http://localhost:8181/v1/data/app/rbac/allow");

    private URI opaGroupUri;

    @SuppressWarnings("unused")
    private static class OpaQuery {
        public OpaQueryInput input;
    }

    @SuppressWarnings("unused")
    private static class OpaQueryInput {
        public AuthorizationRequest request;

        public OpaQueryInput() {
        }

        public OpaQueryInput(AuthorizationRequest request) {
            this.request = request;
        }
    }

    private static class OpaQueryResult {
        public String decision_id;
        public List<String> result;
    }

    public NifiOpaAuthorizer() {
        String configuredUriString = System.getenv(GROUPURIENVNAME);
        URI configuredUri = null;
        if (configuredUriString != null) {
            try {
                configuredUri = new URI(configuredUriString);
            } catch (URISyntaxException e) {
                throw new RuntimeException(e);
            }
            this.opaGroupUri = configuredUri;
        } else {
            this.opaGroupUri = defaultOpaGroupUri;
        }
    }

    @Override
    public AuthorizationResult authorize(AuthorizationRequest request) throws AuthorizationAccessException {
        OpaQuery query = new OpaQuery();
        query.input = new OpaQueryInput(request);

        byte[] queryJson;
        try {
            queryJson = json.writeValueAsBytes(query);
        } catch (JsonProcessingException e) {
            System.out.println("failed to serialize: " + e.getMessage());
            queryJson = null;
        }
        HttpResponse<String> response;
        try {
            response = httpClient.send(
                    HttpRequest.newBuilder(opaGroupUri).header("Content-Type", "application/json")
                            .POST(HttpRequest.BodyPublishers.ofByteArray(queryJson)).build(),
                    HttpResponse.BodyHandlers.ofString());
        } catch (Exception e) {
            throw new AuthorizationAccessException("failed to get groups: " + e.getMessage());
        }
        switch (response.statusCode()) {
            case 200:
                break;
            case 404:
                System.out.println("404");
            default:
                System.out.println("error");
        }
        String responseBody = response.body();
        OpaQueryResult result = null;
        try {
            result = json.readValue(responseBody, OpaQueryResult.class);
        } catch (Exception e) {
            throw new AuthorizationAccessException("error deserializing answer: " + responseBody);
        }
        if (result.result == null) {
            throw new AuthorizationAccessException("result was empty in response: " + result.toString());
        }
        return AuthorizationResult.approved();
    }

    @Override
    public void initialize(AuthorizerInitializationContext authorizerInitializationContext) throws AuthorizerCreationException {

    }

    @Override
    public void onConfigured(AuthorizerConfigurationContext authorizerConfigurationContext) throws AuthorizerCreationException {

    }

    @Override
    public void preDestruction() throws AuthorizerDestructionException {

    }
}

