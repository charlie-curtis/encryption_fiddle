package me.rename.later.resources;

import com.codahale.metrics.annotation.Timed;
import me.rename.later.exceptions.EncryptionExceptionHandler;
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

@Path("/")
@Produces(MediaType.TEXT_PLAIN)
public class EncryptionFiddleResource {

    public EncryptionFiddleResource() {}

    /**
     * //TODO build the base64 into request/ response headers if possible
     * Encrypts plaintext
     * @param plainText String - as of right now, this string must be base 64 encoded
     * @param key String
     * @return
     */
    @Path("encrypt/plaintext/{plainText}/key/{key}")
    @GET
    @Timed
    public Response encrypt(@PathParam("plainText") String plainText, @PathParam("key") String key) {
        try {
            EncryptionStrategy strat = new AESEncryptionStrategy(key.getBytes());
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
     * Decrypts ciphertext
     * @param cipherText String - as of right now, this string must be base64 encoded
     * @param key String
     * @return
     */
    @Path("decrypt/ciphertext/{cipherText}/key/{key}")
    @GET
    @Timed
    public Response decrypt(@PathParam("cipherText") String cipherText, @PathParam("key") String key) {
        try {
            EncryptionStrategy strat = new AESEncryptionStrategy(key.getBytes());
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
