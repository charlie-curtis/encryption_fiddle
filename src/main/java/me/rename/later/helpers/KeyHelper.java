package me.rename.later.helpers;

import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;

import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;

public class KeyHelper
{
    public static final String CIPHER_AES = "AES";
    public static final String CIPHER_RSA = "RSA";
    public static final String PRIVATE_KEY = "private_key";
    public static final String PUBLIC_KEY = "public_key";
    public static final String IV_SPEC = "iv_spec";

    /**
     * @return Base64 encoded private key.
     */
    public static HashMap<String, String> generateAESKey()
    {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(CIPHER_AES);
            keyGenerator.init(256);
            Key key = keyGenerator.generateKey();
            HashMap<String, String> map = new HashMap<>();
            map.put(PRIVATE_KEY, new String(Base64.getEncoder().encode(key.getEncoded())));
            return map;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * @return Base64 encoded public/private key, respectively.
     */
    public static HashMap<String, String> generateRSAKeys()
    {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(CIPHER_RSA);
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            HashMap<String, String> map = new HashMap<>();
            map.put(PUBLIC_KEY, new String(Base64.getEncoder().encode(keyPair.getPublic().getEncoded())));
            map.put(PRIVATE_KEY, new String(Base64.getEncoder().encode(keyPair.getPrivate().getEncoded())));
            return map;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static Key createAESKeyFromEncodedString(String encodedKey)
    {
        byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
        return new SecretKeySpec(decodedKey, CIPHER_AES);
    }

    public static PublicKey createRSAPublicKeyFromBase64EncodedString(String encodedKey)
    {
        try {
            byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decodedKey);
            return KeyFactory.getInstance(CIPHER_RSA).generatePublic(keySpec);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static PrivateKey createRSAPrivateKeyFromBase64EncodedString(String encodedKey)
    {
        try {
            byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedKey);
            return KeyFactory.getInstance(CIPHER_RSA).generatePrivate(keySpec);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static HashMap<String, String> generateKeysForCipher(String cipher)
    {
        HashMap<String, String> generatedKeys;
        switch (cipher) {
            case CIPHER_AES:
                generatedKeys = generateAESKey();
                break;
            case CIPHER_RSA:
                generatedKeys = generateRSAKeys();
                break;
            default:
                generatedKeys = new HashMap<>();
                break;
        }
        return generatedKeys;
    }
}
