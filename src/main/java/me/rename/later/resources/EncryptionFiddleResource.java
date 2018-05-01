package me.rename.later.resources;

import com.codahale.metrics.annotation.Timed;
import me.rename.later.interfaces.EncryptionStrategy;
import me.rename.later.managers.EncryptionManager;
import me.rename.later.strategies.AESEncryptionStrategy;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

@Path("/")
@Produces(MediaType.TEXT_PLAIN)
public class EncryptionFiddleResource {

    /*
    private final String template;
    private final String defaultName;
    private final AtomicLong counter;
    */
    public EncryptionFiddleResource(String template, String defaultName) {
/*        this.template = template;
        this.defaultName = defaultName;
        this.counter = new AtomicLong();
*/
    }

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
        } catch (Exception e) {
            //TODO fix this blanket exception
            return Response.status(Response.Status.BAD_REQUEST).build();
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
        } catch (Exception e) {
            //TODO fix this blanket exception
            return Response.status(Response.Status.BAD_REQUEST).build();
        }

    }
}
