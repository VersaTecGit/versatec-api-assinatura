package com.versatec.services;

import com.versatec.domain.SignatureJob;
import com.versatec.repository.SignatureJobRepository;
import com.versatec.utils.FileUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.nio.file.Path;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SignatureJobCleanupServiceTest {

    @Mock
    private SignatureJobRepository jobRepository;

    @Mock
    private FileUtils fileUtils;

    private SignatureJobCleanupService cleanupService;

    @BeforeEach
    void setUp() {
        cleanupService = new SignatureJobCleanupService(jobRepository, fileUtils, 7);
    }

    @Test
    void expirePendingJobs_shouldCallRepositoryExpireOldJobs() {
        when(jobRepository.expireOldJobs(any(Instant.class))).thenReturn(2);

        cleanupService.expirePendingJobs();

        verify(jobRepository, times(1)).expireOldJobs(any(Instant.class));
    }

    @Test
    void purgeOldJobs_whenNoOldJobs_shouldDoNothing() {
        when(jobRepository.findJobsOlderThan(any(Instant.class))).thenReturn(Collections.emptyList());

        cleanupService.purgeOldJobs();

        verify(jobRepository, never()).deleteAll(any());
        verifyNoInteractions(fileUtils);
    }

    @Test
    void purgeOldJobs_shouldDeletePhysicalFilesAndRemoveFromRepository() throws Exception {
        SignatureJob job1 = SignatureJob.builder()
                .id(UUID.randomUUID())
                .originalFilePath("/tmp/orig1.xml")
                .build();
        job1.complete("/tmp/signed1.xml", "signed1.xml");

        SignatureJob job2 = SignatureJob.builder()
                .id(UUID.randomUUID())
                .originalFilePath("/tmp/orig2.xml")
                .build();

        List<SignatureJob> oldJobs = List.of(job1, job2);
        when(jobRepository.findJobsOlderThan(any(Instant.class))).thenReturn(oldJobs);

        cleanupService.purgeOldJobs();

        verify(fileUtils, times(1)).removeFile(Path.of("/tmp/orig1.xml"));
        verify(fileUtils, times(1)).removeFile(Path.of("/tmp/signed1.xml"));
        verify(fileUtils, times(1)).removeFile(Path.of("/tmp/orig2.xml"));
        verify(jobRepository, times(1)).deleteAll(oldJobs);
    }
}
