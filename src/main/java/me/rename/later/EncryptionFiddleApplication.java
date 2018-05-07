package me.rename.later;

import io.dropwizard.Application;
import io.dropwizard.setup.Bootstrap;
import io.dropwizard.setup.Environment;
import me.rename.later.resources.EncryptionFiddleResource;
import org.eclipse.jetty.servlets.CrossOriginFilter;

import javax.servlet.DispatcherType;
import javax.servlet.FilterRegistration;
import java.util.EnumSet;

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


        //TODO see if I can get rid of this bit once it's shipped to prod
        //it's currently necessary because ember local development runs on its
        //own server

        final EncryptionFiddleResource resource = new EncryptionFiddleResource();
        final FilterRegistration.Dynamic cors =
            environment.servlets().addFilter("CORS", CrossOriginFilter.class);

        // Configure CORS parameters
        cors.setInitParameter("allowedOrigins", "http://localhost:4200");
        cors.setInitParameter("allowedHeaders", "X-Requested-With,Content-Type,Accept,Origin");
        cors.setInitParameter("allowedMethods", "OPTIONS,GET,PUT,POST,DELETE,HEAD");

        // Add URL mapping
        cors.addMappingForUrlPatterns(EnumSet.allOf(DispatcherType.class), true, "/*");
        environment.jersey().register(resource);
    }
}
