package tn.keycloak.commun;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;

import org.springframework.http.HttpEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

@Service
public class TokenService {

    String clientSecret;
    String clientId;
    String tokenExchangeGrantType;
    String keycloakServerURL;
    String keycloakRealm;

    /**
    * this method returns if the JWT token is expired
    */
    public boolean isTokenExpired(String token){
        boolean isExpired=false;
        try {
            JWT jwt = JWTParser.parse(token);
            JWTClaimsSet claimsSet = jwt.getJWTClaimsSet();
            Date expirationTime = claimsSet.getExpirationTime();
            Date current = new Date();
            if(current.after(expirationTime)){
                isExpired=true;
            }
        }catch (ParseException e){
            System.out.println("error occurred when parsing token");
        }
        return isExpired;
    }
    /**
    * this method returns the JWT token expiry date
    */
    public Date getTokenExpirydate(String token){
        Date expirationdate = null;
        try {
            JWT jwt = JWTParser.parse(token);
            JWTClaimsSet claimsSet = jwt.getJWTClaimsSet();
            expirationdate = claimsSet.getExpirationTime();
        }catch (ParseException e){
            System.out.println("error occurred when parsing token");
        }
        return expirationdate;
    }

    /**
    * this method exchange a JWT token. you have to configure token_exchange in keycloak server
    */
    public String exchangeToken(String token){
        String exchangedToken="";
        RestTemplate restTemplate=new RestTemplate();
        HttpHeaders headers=new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", tokenExchangeGrantType);
        body.add("client_id", clientId);
        body.add("client_secret", clientSecret);
        body.add("subject_token",token);
        String issuer ="";
        try {
            JWT jwt = JWTParser.parse(token);
            JWTClaimsSet claimsSet = jwt.getJWTClaimsSet();
            issuer = claimsSet.getIssuer();
        }catch (ParseException e){
            System.out.println("error occurred when parsing token");
        }
        ResponseEntity<String> response=null;
        try {
            response = restTemplate.postForEntity(
                    issuer + "/protocol/openid-connect/token",
                    new HttpEntity<>(body, headers),
                    String.class
            );
            if(!extractFieldFromKeycloakResponse(response.getBody().toString(),"access_token").isEmpty()){
                exchangedToken=extractFieldFromKeycloakResponse(response.getBody().toString(),"access_token");
            }
        }catch (NullPointerException | HttpClientErrorException e){
            System.out.println("token exchange process failed");
        }


        return  exchangedToken;
    }

    /**
    * this method impersonate the user using its ID and the client specified
    */
    public String impersonateUser(String token){
        String userId=getUserId(token);
        String newAccessToken="";
        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", tokenExchangeGrantType);
        body.add("client_id", clientId);
        body.add("client_secret", clientSecret);
        body.add("requested_subject", userId);
        String issuer = keycloakServerURL + "/realms/" + keycloakRealm;
        ResponseEntity<String> response;
        try {
            response = restTemplate.postForEntity(
                    issuer + "/protocol/openid-connect/token",
                    new HttpEntity<>(body, headers),
                    String.class
            );
            if (!extractFieldFromKeycloakResponse(response.getBody(), "access_token").isEmpty()) {
                newAccessToken = extractFieldFromKeycloakResponse(response.getBody(), "access_token");
            }
        } catch (NullPointerException | HttpClientErrorException e) {
            System.out.println("token refreshing process failed");
        }
      
        return  newAccessToken;
    }

    /**
    * this method extracts a field(access_token, refresh_token,...) from keycloak token endpoint response.
    */
    public static String extractFieldFromKeycloakResponse(String jsonResponse,String field) {
        String extractedToken="";
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            JsonNode jsonNode = objectMapper.readTree(jsonResponse);
            extractedToken = jsonNode.get(field).asText();
        } catch (NullPointerException | JsonProcessingException e) {
            // Handle parsing or other exceptions
            System.out.println("Failed to extract "+field);
        }
        return extractedToken;
    }

    /**
    * this method gets the userId from JWT token.
    */
    public String getUserId(String token){
        String userId="";
        try {
            JWT jwt = JWTParser.parse(token);
            JWTClaimsSet claimsSet = jwt.getJWTClaimsSet();
            userId = claimsSet.getSubject();
        }catch (ParseException e){
            System.out.println("error occurred when parsing token");
        }
        return userId;
    }

    /**
    * this method extract "realm_access" roles from JWT token.
    */
     public List<String > extractRoles(String token)  {
        List<String> roles=new ArrayList<String>();
        try{
            JWT jwt = JWTParser.parse(token);
            JWTClaimsSet claimsSet = jwt.getJWTClaimsSet();
            Map<String, Object> realmAccessRoles = claimsSet.getJSONObjectClaim("realm_access");
            String[] rolesFromClaim=realmAccessRoles.get("roles").toString().substring(1, realmAccessRoles.get("roles").toString().length() - 1).split(",");
            for(String role:rolesFromClaim){
                roles.add(role.substring(1,role.length()-1));
            }
        }catch (ParseException e){
            System.out.println("Error while parsing token");
        }
        return roles;
    }

    /**
    * this method extract groups from JWT token.
    */
    public List<String > extractGroups(String token)  {
        List<String> groups=new ArrayList<String>();
        try{
            JWT jwt = JWTParser.parse(token);
            JWTClaimsSet claimsSet = jwt.getJWTClaimsSet();
            String[] groupsClaim = claimsSet.getStringArrayClaim("groups");
            for(String group:groupsClaim){
                groups.add(group.substring(1));
            }
        }catch (ParseException e){
            System.out.println("Error while parsing token");
        }
        return groups;
    }

    /**
    * this method extract token id from JWT token.
    */
    public String getJTI(String token){
        String jti="";
        try {
            JWT jwt = JWTParser.parse(token);
            JWTClaimsSet claimsSet = jwt.getJWTClaimsSet();
            jti = claimsSet.getJWTID();
        }catch (ParseException e){
            System.out.println("error occurred when parsing token");
        }
        return jti;
    }

    /**
    * this method extract the list of audience from JWT token.
    */
    public List<String> getAudience(String token){
        List<String> audience= new ArrayList<>();
        try {
            JWT jwt = JWTParser.parse(token);
            JWTClaimsSet claimsSet = jwt.getJWTClaimsSet();
            audience = claimsSet.getAudience();
        }catch (ParseException e){
            System.out.println("error occurred when parsing token");
        }
        return audience;
    }
}
