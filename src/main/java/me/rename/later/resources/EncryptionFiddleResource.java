package me.rename.later.resources;

import com.codahale.metrics.annotation.Timed;
import me.rename.later.exceptions.EncryptionExceptionHandler;
import me.rename.later.helpers.KeyHelper;
import me.rename.later.interfaces.EncryptionStrategy;
import me.rename.later.managers.EncryptionManager;
import me.rename.later.strategies.AESEncryptionStrategy;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.util.HashMap;

//TODO make API in README.md
@Path("/")
@Produces(MediaType.TEXT_PLAIN)
public class EncryptionFiddleResource {

    public EncryptionFiddleResource() {}

    /**
     * Generates a key or set of keys based on the cipher.
     * The return keys are base64encoded.
     * @param cipher
     * @return
     */
    @Path("generate/keys/{cipher}")
    @GET
    @Timed
    @Produces(MediaType.APPLICATION_JSON)
    public Response generateKeys(@PathParam("cipher") String cipher) throws GeneralSecurityException {

        //TODO move this somewhere else.
        HashMap<String, String> generatedKeys;
        switch (cipher) {
            case "AES":
                generatedKeys = KeyHelper.generateAESKey();
                break;
            case "RSA":
                generatedKeys = KeyHelper.generateRSAKeys();
                break;
            default:
                generatedKeys = new HashMap<>();
                break;
        }
        return Response.ok(generatedKeys).build();
    }
    /**
     * Encrypts plaintext using the AES Encryption Algorithm
     * @param plainText String - as of right now, this string must be base 64 encoded
     * @param key String
     * @return
     */
    @Path("encrypt/aes/text/{plainText}/key/{key}")
    @GET
    @Timed
    public Response aesEncrypt(@PathParam("plainText") String plainText, @PathParam("key") String key) {
        try {
            Key secretKey = KeyHelper.createAESKeyFromBase64EncodedString(key);
            EncryptionStrategy strat = new AESEncryptionStrategy(secretKey);
            EncryptionManager manager = new EncryptionManager(strat);
            byte[] cipherText = manager.encrypt(plainText.getBytes());
            return Response.ok(new String(cipherText)).build();
        } catch (GeneralSecurityException e) {
            if (EncryptionExceptionHandler.isClientError(e)) {
                return Response.status(Response.Status.BAD_REQUEST).entity(e.getMessage()).build();
            }
            e.printStackTrace();
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * Decrypts ciphertext using the AES Encryption algorithm
     * @param cipherText String - as of right now, this string must be base64 encoded
     * @param key String
     * @return
     */
    @Path("decrypt/aes/text/{cipherText}/key/{key}")
    @GET
    @Timed
    public Response aesDecrypt(@PathParam("cipherText") String cipherText, @PathParam("key") String key) {
        try {
            Key secretKey = KeyHelper.createAESKeyFromBase64EncodedString(key);
            EncryptionStrategy strat = new AESEncryptionStrategy(secretKey);
            EncryptionManager manager = new EncryptionManager(strat);
            byte[] plainText = manager.decrypt(cipherText.getBytes());
            return Response.ok(new String(plainText)).build();
        } catch (GeneralSecurityException e) {
            if (EncryptionExceptionHandler.isClientError(e)) {
                return Response.status(Response.Status.BAD_REQUEST).entity(e.getMessage()).build();
            }
            e.printStackTrace();
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
        }
    }
}
