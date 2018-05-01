package me.rename.later.resources;

import com.codahale.metrics.annotation.Timed;
import me.rename.later.interfaces.EncryptionStrategy;
import me.rename.later.managers.EncryptionManager;
import me.rename.later.strategies.AESEncryptionStrategy;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
//import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.concurrent.atomic.AtomicLong;
//import java.util.Optional;

@Path("/")
@Produces(MediaType.APPLICATION_JSON)
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

    @Path("encrypt/plaintext/{plainText}/key/{key}")
    @GET
    @Timed
    public Response encrypt(@PathParam("plainText") String plainText, @PathParam("key") String key) {
        try {
            EncryptionStrategy strat = new AESEncryptionStrategy(key.getBytes());
            EncryptionManager manager = new EncryptionManager(strat);
            byte[] cipherText = manager.encrypt(plainText.getBytes());
            return Response.ok(cipherText).build();
        } catch (Exception e) {
            //TODO fix this blanket exception
            return Response.status(Response.Status.BAD_REQUEST).build();
        }

    }
}
