package me.rename.later.helpers;

import sun.security.rsa.RSAKeyFactory;

import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;

import java.security.interfaces.RSAKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;

public class KeyHelper
{
    public static final String PRIVATE_KEY = "private_key";
    public static final String PUBLIC_KEY = "public_key";

    /**
     * @return Base64 encoded private key
     */
    public static HashMap<String, String> generateAESKey() throws GeneralSecurityException
    {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        Key key = keyGenerator.generateKey();
        HashMap<String, String> map = new HashMap<>();
        map.put(PRIVATE_KEY, new String(Base64.getEncoder().encode(key.getEncoded())));
        return map;
    }

    /**
     * @return Base64 encoded public/private key, respectively.
     */
    public static HashMap<String, String> generateRSAKeys() throws GeneralSecurityException
    {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        HashMap<String, String> map = new HashMap<>();
        System.out.println("The format is " + keyPair.getPublic().getFormat());
        System.out.println("The format is " + keyPair.getPrivate().getFormat());
        map.put(PUBLIC_KEY, new String(Base64.getEncoder().encode(keyPair.getPublic().getEncoded())));
        map.put(PRIVATE_KEY, new String(Base64.getEncoder().encode(keyPair.getPrivate().getEncoded())));
        return map;
    }

    public static Key createAESKeyFromBase64EncodedString(String encodedKey)
    {
        byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
        return new SecretKeySpec(decodedKey, "AES");
    }

    public static PublicKey createRSAPublicKeyFromBase64EncodedString(String encodedKey) throws GeneralSecurityException
    {
        byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decodedKey);
        return KeyFactory.getInstance("RSA").generatePublic(keySpec);
    }

    public static PrivateKey createRSAPrivateKeyFromBase64EncodedString(String encodedKey) throws GeneralSecurityException
    {
        byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedKey);
        return KeyFactory.getInstance("RSA").generatePrivate(keySpec);
    }
}
