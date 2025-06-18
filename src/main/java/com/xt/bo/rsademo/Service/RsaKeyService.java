package com.xt.bo.rsademo.Service;

import com.xt.bo.rsademo.Payload.DeviceRequest;
import com.xt.bo.rsademo.models.Response.KeyResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

@Service
@RequiredArgsConstructor
public class RsaKeyService {
    private final KeyService keyService;

//  This is for Generate Keys Service and Save to database
    public KeyResponse generateAndSaveRsaKeyPair(DeviceRequest request) throws Exception {
        KeyResponse response = new KeyResponse();

//      Generate RSA key pair
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();

//      Getting Client's Key from KeyPairGenerator
        PrivateKey privateKey = pair.getPrivate();
        PublicKey publicKey = pair.getPublic();


//      ===== IMPORTANT * Use standard PEM format (no extra spaces or blank lines), as client parsing is strict * IMPORTANT =====
        String pemPublic = convertToPem("PUBLIC KEY", publicKey.getEncoded());
        String pemPrivate = convertToPem("PRIVATE KEY", privateKey.getEncoded());
//      ===== IMPORTANT * Use standard PEM format (no extra spaces or blank lines), as client parsing is strict * IMPORTANT =====


//      Read server's public key from file to include in the response
        InputStream inputStream = getClass().getClassLoader().getResourceAsStream("public.pem");
        String key = new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);


//      Set Client's Keys and Server public key for response back to client
        response.setClientPrivateKey(pemPrivate);
        response.setClientPublicKey(pemPublic);
        response.setServerPublicKey(key);

//      Save to database for Client's Key
        keyService.saveKey(pemPublic, pemPrivate, request);

        return response;
    }

//   Convert keys to Base64-encoded strings so they can be sent as JSON
    private String convertToPem(String type, byte[] encoded) {
        String base64 = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(encoded);
        return "-----BEGIN " + type + "-----\n" + base64 + "\n-----END " + type + "-----\n";
    }

    public KeyResponse getServerKey() throws Exception {
        KeyResponse response = new KeyResponse();

//      Read server's public key from file to include in the response
        InputStream inputStream = getClass().getClassLoader().getResourceAsStream("public.pem");
        String key = new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);

//      Set Client's Keys and Server public key for response back to client
        response.setServerPublicKey(key);


        return response;
    }
}
