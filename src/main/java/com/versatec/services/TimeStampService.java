package com.versatec.services;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.apache.http.HttpEntity;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

@Service
public class TimeStampService {

    @Value("${tsa.url}")
    private String tsaUrl;

    @Value("${serpro.auth.token.url}")
    private String serproAuthTokenUrl;

    @Value("${serpro.auth.consumer.key}")
    private String serproAuthConsumerKey;

    @Value("${serpro.auth.consumer.secret}")
    private String serproAuthConsumerSecret;

    /**
     * Faz uma requisição para a API de autenticação do SERPRO para obter um token
     * de acesso.
     *
     * @return O token de acesso em formato de String.
     * @throws Exception se a requisição falhar ou o token não for encontrado.
     */
    public String getAccessToken() throws Exception {
        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpPost httpPost = new HttpPost(serproAuthTokenUrl);

            String encodedCredentials = this.getEncodedCredentials();

            httpPost.setHeader("Authorization", "Basic " + encodedCredentials);

            List<BasicNameValuePair> params = new ArrayList<>();
            params.add(new BasicNameValuePair("grant_type", "client_credentials"));
            httpPost.setEntity(new UrlEncodedFormEntity(params, StandardCharsets.UTF_8));

            try (CloseableHttpResponse response = httpClient.execute(httpPost)) {
                String jsonResponse = EntityUtils.toString(response.getEntity());

                if (response.getStatusLine().getStatusCode() == 200) {
                    ObjectMapper objectMapper = new ObjectMapper();
                    JsonNode rootNode = objectMapper.readTree(jsonResponse);
                    return rootNode.get("access_token").asText();
                } else {
                    throw new Exception("Falha ao obter o token de acesso. Status: " +
                            response.getStatusLine().getStatusCode());
                }
            }
        }
    }

    /**
     * Codifica as credenciais do consumidor em Base64.
     *
     * @return As credenciais codificadas em Base64.
     */
    public String getEncodedCredentials() {
        String credentials = serproAuthConsumerKey + ":" + serproAuthConsumerSecret;
        return Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
    }
}