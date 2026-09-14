package com.versatec.repository;

import com.versatec.domain.JobStatus;
import com.versatec.domain.SignatureJob;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.test.context.TestPropertySource;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@DataJpaTest
@TestPropertySource(properties = {
        "spring.flyway.enabled=false",
        "spring.jpa.hibernate.ddl-auto=create-drop",
        "spring.datasource.url=jdbc:h2:mem:testdb;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DEFAULT_NULL_ORDERING=HIGH"
})
class SignatureJobRepositoryTest {

    @Autowired
    private SignatureJobRepository repository;

    @Test
    void saveAndFindById_shouldPersistCorrectlyInH2() {
        SignatureJob job = SignatureJob.builder()
                .userId("user-100")
                .documentHash("hash-123456")
                .originalFilePath("/tmp/orig.xml")
                .originalFileName("orig.xml")
                .build();

        SignatureJob saved = repository.save(job);
        assertNotNull(saved.getId());

        SignatureJob found = repository.findById(saved.getId()).orElse(null);
        assertNotNull(found);
        assertEquals("user-100", found.getUserId());
        assertEquals("hash-123456", found.getDocumentHash());
        assertEquals(JobStatus.PENDING, found.getStatus());
        assertNull(found.getTargetXPath());
    }

    @Test
    void saveAndFindById_withTargetXPath_shouldPersistCorrectly() {
        SignatureJob job = SignatureJob.builder()
                .userId("user-xpath")
                .documentHash("hash-xpath")
                .originalFilePath("/tmp/orig2.xml")
                .originalFileName("orig2.xml")
                .targetXPath("//TargetNode")
                .build();

        SignatureJob saved = repository.save(job);
        assertNotNull(saved.getId());

        SignatureJob found = repository.findById(saved.getId()).orElseThrow();
        assertEquals("//TargetNode", found.getTargetXPath());
    }

    @Test
    void expireOldJobs_shouldMarkPendingAsExpired() {
        Instant past = Instant.now().minus(30, ChronoUnit.MINUTES);
        SignatureJob expiredPending = SignatureJob.builder()
                .userId("user-1")
                .documentHash("hash-1")
                .originalFilePath("/tmp/1.xml")
                .originalFileName("1.xml")
                .expiresAt(past)
                .build();

        repository.save(expiredPending);

        int updatedCount = repository.expireOldJobs(Instant.now());
        assertEquals(1, updatedCount);

        SignatureJob afterExpire = repository.findById(expiredPending.getId()).orElseThrow();
        assertEquals(JobStatus.EXPIRED, afterExpire.getStatus());
    }

    @Test
    void findJobsOlderThan_shouldReturnOnlyJobsBeforeCutoff() {
        SignatureJob job = SignatureJob.builder()
                .userId("user-old")
                .documentHash("hash-old")
                .originalFilePath("/tmp/old.xml")
                .originalFileName("old.xml")
                .build();

        repository.save(job);

        // Como o job foi criado agora, um cutoff no futuro deve encontrá-lo
        List<SignatureJob> foundFuture = repository.findJobsOlderThan(Instant.now().plusSeconds(60));
        assertFalse(foundFuture.isEmpty());

        // Um cutoff no passado não deve encontrá-lo
        List<SignatureJob> foundPast = repository.findJobsOlderThan(Instant.now().minusSeconds(60));
        assertTrue(foundPast.isEmpty());
    }
}
