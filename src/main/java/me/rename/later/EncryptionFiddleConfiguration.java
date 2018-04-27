package me.rename.later;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.dropwizard.Configuration;
import org.hibernate.validator.constraints.NotEmpty;
//import com.fasterxml.jackson.annotation.JsonProperty;
//import org.hibernate.validator.constraints.NotEmpty;

public class EncryptionFiddleConfiguration extends Configuration {

    @NotEmpty
    private String appName;

    @JsonProperty
    public void setAppName(String name)
    {
        this.appName = name;
    }
}
