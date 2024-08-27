package com.versatec.mocks;

import com.versatec.config.AppProperties;

public class AppPropertiesMock {

    public static AppProperties create() {
        var appProperties = new AppProperties();
        appProperties.setUrl("https://www.example.com.br");
        return appProperties;
    }
}
