package me.rename.later.resources;

import com.codahale.metrics.annotation.Timed;
import me.rename.later.helpers.KeyHelper;
import me.rename.later.interfaces.EncryptionStrategy;
import me.rename.later.managers.EncryptionManager;
import me.rename.later.strategies.AESEncryptionStrategy;
import me.rename.later.strategies.RSAEncryptionStrategy;

import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;

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
    public Response generateKeys(@PathParam("cipher") String cipher)
    {
        return Response.ok(KeyHelper.generateKeysForCipher(cipher)).build();
    }
    //TODO consolidate the encryption endpoints into one.
    /**
     * Encrypts plaintext using the input cipher
     * @param plainText String - as of right now, this string must be base 64 encoded
     * @param key String
     * @return
     */
    @Path("encrypt")
    @POST
    @Timed
    @Produces(MediaType.APPLICATION_JSON)
    public Response encrypt(@FormParam("text") String plainText, @FormParam("key") String key,
                                @FormParam("cipher") String cipher) {

        EncryptionStrategy strat;
        if (cipher.equals(KeyHelper.CIPHER_AES)) {
            Key secretKey = KeyHelper.createAESKeyFromEncodedString(key);
            strat = new AESEncryptionStrategy(secretKey);
        } else {
            PublicKey publicKey = KeyHelper.createRSAPublicKeyFromBase64EncodedString(key);
            strat = new RSAEncryptionStrategy(publicKey);
        }
        String cipherText = new EncryptionManager(strat).encrypt(plainText);
        HashMap<String, String> map = new HashMap<>();
        map.put("msg", cipherText);
        return Response.ok(map).build();
    }

    /**
     * Decrypts ciphertext using the input cipher
     * @param cipherText String - as of right now, this string must be base64 encoded
     * @param key String
     * @return
     */
    @Path("decrypt")
    @POST
    @Timed
    @Produces(MediaType.APPLICATION_JSON)
    public Response decrypt(@FormParam("text") String cipherText, @FormParam("key") String key,
                            @FormParam("cipher") String cipher) {
        EncryptionStrategy strat;
        if (cipher.equals(KeyHelper.CIPHER_AES)) {
            Key secretKey = KeyHelper.createAESKeyFromEncodedString(key);
            strat = new AESEncryptionStrategy(secretKey);
        } else {
            PrivateKey privateKey = KeyHelper.createRSAPrivateKeyFromBase64EncodedString(key);
            strat = new RSAEncryptionStrategy(privateKey);
        }
        String plainText = new EncryptionManager(strat).decrypt(cipherText);
        HashMap<String, String> map = new HashMap<>();
        map.put("msg", plainText);
        return Response.ok(map).build();
    }
}
