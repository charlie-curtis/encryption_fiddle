package me.rename.later;

import io.dropwizard.Application;
import io.dropwizard.setup.Bootstrap;
import io.dropwizard.setup.Environment;
import me.rename.later.resources.EncryptionFiddleResource;
//import com.example.helloworld.resources.HelloWorldResource;
//import com.example.helloworld.health.TemplateHealthCheck;

public class EncryptionFiddleApplication extends Application<EncryptionFiddleConfiguration>{

    public static void main(String[] args) throws Exception {
        new EncryptionFiddleApplication().run(args);
    }

    @Override
    public String getName() {
        return "encryption-fiddle";
    }

    @Override
    public void initialize(Bootstrap<EncryptionFiddleConfiguration> bootstrap) {
        // nothing to do yet
    }

    @Override
    public void run(EncryptionFiddleConfiguration configuration,
                    Environment environment) {
        // nothing to do yet
        final EncryptionFiddleResource resource = new EncryptionFiddleResource(
            "TODO", "TODO"
        );
        environment.jersey().register(resource);
    }
}
