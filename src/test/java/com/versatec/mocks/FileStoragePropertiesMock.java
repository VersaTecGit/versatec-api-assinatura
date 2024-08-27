package com.versatec.mocks;

import com.versatec.config.FileStorageProperties;

public class FileStoragePropertiesMock {

    public static FileStorageProperties create() {
        var fileStorageProperties = new FileStorageProperties();
        fileStorageProperties.setAssetDir("assets");
        fileStorageProperties.setDownloadDir("downloads");
        fileStorageProperties.setUploadDir("uploads");
        return fileStorageProperties;
    }
}
