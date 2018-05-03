package me.rename.later;

import io.dropwizard.Application;
import io.dropwizard.setup.Bootstrap;
import io.dropwizard.setup.Environment;
import me.rename.later.resources.EncryptionFiddleResource;

public class EncryptionFiddleApplication extends Application<EncryptionFiddleConfiguration>{

    public static void main(String[] args) throws Exception {
        new EncryptionFiddleApplication().run(args);
    }

    @Override
    public String getName() {
        return "encryption-fiddle";
    }

    @Override
    public void initialize(Bootstrap<EncryptionFiddleConfiguration> bootstrap) {}

    @Override
    public void run(EncryptionFiddleConfiguration configuration,
                    Environment environment) {
        final EncryptionFiddleResource resource = new EncryptionFiddleResource();
        environment.jersey().register(resource);
    }
}
