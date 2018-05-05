package me.rename.later.resources;

import com.codahale.metrics.annotation.Timed;
import me.rename.later.exceptions.EncryptionExceptionHandler;
import me.rename.later.helpers.KeyHelper;
import me.rename.later.interfaces.EncryptionStrategy;
import me.rename.later.managers.EncryptionManager;
import me.rename.later.strategies.AESEncryptionStrategy;
import me.rename.later.strategies.RSAEncryptionStrategy;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;

//TODO make API in README.md
@Path("/")
@Produces(MediaType.TEXT_PLAIN)
public class EncryptionFiddleResource {

    public EncryptionFiddleResource() {}

    /**
     * Generates a key or set of keys based on the cipher.
     * The return keys are base64encoded.
     * @param cipher The Encryption Algorithm to be used.
     * @return Response.
     */
    @Path("generate/keys/{cipher}")
    @GET
    @Timed
    @Produces(MediaType.APPLICATION_JSON)
    public Response generateKeys(@PathParam("cipher") String cipher) throws GeneralSecurityException {

        return Response.ok(KeyHelper.generateKeysForCipher(cipher)).build();
    }
    /**
     * Encrypts plaintext using the AES Cipher
     * @param plainText String - as of right now, this string must be base 64 encoded
     * @param key String
     * @return
     */
    @Path("encrypt/AES/text/{plainText}/key/{key}")
    @GET
    @Timed
    public Response aesEncrypt(@PathParam("plainText") String plainText, @PathParam("key") String key) {
        try {
            Key secretKey = KeyHelper.createAESKeyFromBase64EncodedString(key);
            EncryptionManager manager = new EncryptionManager(new AESEncryptionStrategy(secretKey));
            byte[] cipherText = manager.encrypt(plainText.getBytes());
            return Response.ok(new String(cipherText)).build();
        } catch (GeneralSecurityException e) {
            if (EncryptionExceptionHandler.isClientError(e)) {
                return Response.status(Response.Status.BAD_REQUEST).entity(e.getMessage()).build();
            }
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * Decrypts ciphertext using the AES Cipher
     * @param cipherText String - as of right now, this string must be base64 encoded
     * @param key String
     * @return
     */
    @Path("decrypt/AES/text/{cipherText}/key/{key}")
    @GET
    @Timed
    public Response aesDecrypt(@PathParam("cipherText") String cipherText, @PathParam("key") String key) {
        try {
            Key secretKey = KeyHelper.createAESKeyFromBase64EncodedString(key);
            EncryptionManager manager = new EncryptionManager(new AESEncryptionStrategy(secretKey));
            byte[] plainText = manager.decrypt(cipherText.getBytes());
            return Response.ok(new String(plainText)).build();
        } catch (GeneralSecurityException e) {
            if (EncryptionExceptionHandler.isClientError(e)) {
                return Response.status(Response.Status.BAD_REQUEST).entity(e.getMessage()).build();
            }
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * Decrypts ciphertext using the RSA Cipher
     * @param cipherText String - as of right now, this string must be base64 encoded
     * @param key String
     * @return
     */
    @Path("decrypt/RSA/text/{cipherText}/key/{key}")
    @GET
    @Timed
    public Response rsaDecrypt(@PathParam("cipherText") String cipherText, @PathParam("key") String key) {
        try {
            PrivateKey privateKey = KeyHelper.createRSAPrivateKeyFromBase64EncodedString(key);
            EncryptionManager manager = new EncryptionManager(new RSAEncryptionStrategy(privateKey));
            byte[] plainText = manager.decrypt(cipherText.getBytes());
            return Response.ok(new String(plainText)).build();
        } catch (GeneralSecurityException e) {
            if (EncryptionExceptionHandler.isClientError(e)) {
                return Response.status(Response.Status.BAD_REQUEST).entity(e.getMessage()).build();
            }
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
        }
    }
    /**
     * Encrypts plaintext using the RSA Encryption algorithm
     * @param plainText String - as of right now, this string must be base64 encoded
     * @param key String
     * @return
     */
    @Path("encrypt/RSA/text/{plainText}/key/{key}")
    @GET
    @Timed
    public Response rsaEncrypt(@PathParam("plainText") String plainText, @PathParam("key") String key) {
        try {
            PublicKey publicKey = KeyHelper.createRSAPublicKeyFromBase64EncodedString(key);
            EncryptionManager manager = new EncryptionManager(new RSAEncryptionStrategy(publicKey));
            byte[] cipherText = manager.encrypt(plainText.getBytes());
            return Response.ok(new String(cipherText)).build();
        } catch (GeneralSecurityException e) {
            if (EncryptionExceptionHandler.isClientError(e)) {
                return Response.status(Response.Status.BAD_REQUEST).entity(e.getMessage()).build();
            }
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
        }
    }
}
