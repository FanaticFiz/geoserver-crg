/* (c) 2016 Open Source Geospatial Foundation - all rights reserved
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security.oauth2.services;

import io.jsonwebtoken.Jwts;
import org.geoserver.security.oauth2.GeoServerOAuthRemoteTokenServices;

import java.util.Base64;
import java.util.Map;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Remote Token Services for Google token details.
 *
 * @author Alessio Fabiani, GeoSolutions S.A.S.
 */
public class GoogleTokenServices extends GeoServerOAuthRemoteTokenServices {

    public GoogleTokenServices() {
        super(new GoogleAccessTokenConverter());
    }

    @Override
    protected Map<String, Object> checkToken(String accessToken) {
        try {
            LOGGER.debug("CRG check access token [{}]", accessToken);

            return Jwts.parser()
                       .setSigningKey(clientSecret.getBytes())
                       .parseClaimsJws(accessToken)
                       .getBody();
        } catch (Exception e) {
            LOGGER.error("Failed to parse access token. Reason => {}", e.getMessage(), e);

            return Map.of();
        }
    }

    @Override
    protected void transformNonStandardValuesToStandardValues(Map<String, Object> map) {
        LOGGER.debug("Original map = {}", map);

        map.put("client_id", map.get("user_name"));

        LOGGER.debug("Transformed = {}", map);
    }

    @Override
    protected String getAuthorizationHeader(String accessToken) {
        String creds = "%s:%s".formatted(clientId, clientSecret);

        return "Basic " + new String(Base64.getEncoder().encode(creds.getBytes(UTF_8)));
    }
}
