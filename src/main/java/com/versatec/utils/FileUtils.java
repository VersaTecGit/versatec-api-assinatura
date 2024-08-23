package com.versatec.utils;

import com.versatec.customs.FileLocationEnum;
import com.versatec.config.FileStorageProperties;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Objects;
import java.util.UUID;

@Component
public class FileUtils {

    private final Path fileAssetLocation;
    private final Path fileUploadLocation;
    private final Path fileDownloadLocation;

    public FileUtils(FileStorageProperties fileStorageLocation) {
        this.fileAssetLocation = Paths.get(fileStorageLocation.getAssetDir()).toAbsolutePath().normalize();
        this.fileUploadLocation = Paths.get(fileStorageLocation.getUploadDir()).toAbsolutePath().normalize();
        this.fileDownloadLocation = Paths.get(fileStorageLocation.getDownloadDir()).toAbsolutePath().normalize();
    }

    public File getFile(String fileName, FileLocationEnum location) {
        Path filePath = this.getFilePath(fileName, location);
        return filePath.toFile();
    }

    public Path uploadFile(MultipartFile file, FileLocationEnum location) throws IOException {
        String fileHash = this.getRandomHash() + "_" + file.getOriginalFilename();;
        String fileName = StringUtils.cleanPath(Objects.requireNonNull(fileHash));
        Path fileLocation = this.getFilePath(fileName, location);
        file.transferTo(fileLocation);
        return fileLocation;
    }

    public Path uploadBytes(MultipartFile file, FileLocationEnum location) throws IOException {
        String fileHash = this.getRandomHash() + "_" + file.getOriginalFilename();
        byte[] bytes = file.getBytes();
        String byteFileName = StringUtils.cleanPath(Objects.requireNonNull(fileHash));
        Path byteFileLocation = this.getFilePath(byteFileName, location);
        FileOutputStream fos = new FileOutputStream(byteFileLocation.toString());
        fos.write(bytes);
        fos.close();
        return byteFileLocation;
    }

    public void removeFile(Path filePath) throws IOException {
        if(filePath !=null) {
            Files.deleteIfExists(filePath);
        }
    }

    private String getRandomHash() {
        UUID uuid = UUID.randomUUID();
        return uuid.toString();
    }

    /**
     * Retorna o caminho completo para um arquivo com base na localização informada.
     *
     * @param fileName o nome do arquivo
     * @param location a localização do arquivo
     *
     * @return o caminho completo e normalizado para o arquivo
     */
    public Path getFilePath(String fileName, FileLocationEnum location)
    {
        Path path = switch (location) {
            case ASSET -> this.fileAssetLocation;
            case UPLOAD -> this.fileUploadLocation;
            case DOWNLOAD -> this.fileDownloadLocation;
        };

        return path.resolve(fileName).normalize();
    }
}
