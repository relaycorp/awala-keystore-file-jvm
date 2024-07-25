package tech.relaycorp.awala.keystores.file

import java.io.IOException
import java.time.Instant
import java.time.ZonedDateTime
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.condition.DisabledOnOs
import org.junit.jupiter.api.condition.OS
import tech.relaycorp.relaynet.issueGatewayCertificate
import tech.relaycorp.relaynet.pki.CertificationPath
import tech.relaycorp.relaynet.testing.pki.KeyPairSet
import tech.relaycorp.relaynet.testing.pki.PDACertPath

@ExperimentalCoroutinesApi
@Suppress("BlockingMethodInNonBlockingContext")
internal class FileCertificateStoreTest : KeystoreTestCase() {
    private val storeRootFile = keystoreRoot.directory.resolve("certificate")

    private val certificate =
        issueGatewayCertificate(
            KeyPairSet.PRIVATE_GW.public,
            KeyPairSet.INTERNET_GW.private,
            validityEndDate = ZonedDateTime.now().plusHours(1),
            validityStartDate = ZonedDateTime.now().minusSeconds(1),
        )
    private val chain = listOf(PDACertPath.INTERNET_GW)
    private val issuerId = PDACertPath.INTERNET_GW.subjectId
    private val subjectId = certificate.subjectId
    private val issuerFolder = storeRootFile.resolve(issuerId)
    private val subjectFolder = issuerFolder.resolve(subjectId)

    private val longerCertificate =
        issueGatewayCertificate(
            KeyPairSet.PRIVATE_GW.public,
            KeyPairSet.INTERNET_GW.private,
            validityEndDate = ZonedDateTime.now().plusHours(10),
            validityStartDate = ZonedDateTime.now().minusSeconds(1),
        )
    private val aboutToExpireCertificate =
        issueGatewayCertificate(
            KeyPairSet.PRIVATE_GW.public,
            KeyPairSet.INTERNET_GW.private,
            validityEndDate = ZonedDateTime.now().plusNanos(100_000_000),
            validityStartDate = ZonedDateTime.now().minusSeconds(1),
        )
    private val unrelatedCertificate = PDACertPath.PRIVATE_ENDPOINT

    @Test
    fun `Root directory should be exposed`() {
        val keystore = FileCertificateStore(keystoreRoot)

        assertEquals(storeRootFile, keystore.rootDirectory)
    }

    @Nested
    inner class SaveData {
        @Test
        fun `Certificate should be stored and retrieved`() =
            runTest {
                val keystore = FileCertificateStore(keystoreRoot)

                keystore.save(CertificationPath(certificate, chain), issuerId)

                val result = keystore.retrieveAll(subjectId, issuerId)
                assertEquals(1, result.size)
                assertEquals(
                    certificate.serialize().asList(),
                    result
                        .first()
                        .leafCertificate
                        .serialize()
                        .asList(),
                )
                assertEquals(
                    chain.map { it.serialize().asList() },
                    result.first().certificateAuthorities.map { it.serialize().asList() },
                )

                val addressFiles = subjectFolder.listFiles()!!
                assertEquals(1, addressFiles.size)
                with(addressFiles.first()) {
                    assertTrue(exists())
                    assertTrue(
                        name.startsWith("${certificate.expiryDate.toInstant().toEpochMilli()}-"),
                    )
                }
            }

        @Test
        fun `Certificate stored multiple times should override`() =
            runTest {
                val keystore = FileCertificateStore(keystoreRoot)

                repeat(3) {
                    keystore.save(CertificationPath(certificate, chain), issuerId)
                }

                val result = keystore.retrieveAll(subjectId, issuerId)
                assertEquals(1, result.size)
                assertEquals(
                    certificate.serialize().asList(),
                    result
                        .first()
                        .leafCertificate
                        .serialize()
                        .asList(),
                )
                assertEquals(
                    chain.map { it.serialize().asList() },
                    result.first().certificateAuthorities.map { it.serialize().asList() },
                )

                val addressFiles = subjectFolder.listFiles()!!
                assertEquals(1, addressFiles.size)
            }

        @Test
        internal fun `Certificates by different issuers should not override`() =
            runTest {
                val keystore = FileCertificateStore(keystoreRoot)

                keystore.save(CertificationPath(certificate, chain), issuerId)
                keystore.save(CertificationPath(certificate, emptyList()), issuerId + "diff")

                val result = keystore.retrieveAll(subjectId, issuerId)
                assertEquals(1, result.size)
                assertEquals(
                    certificate.serialize().asList(),
                    result
                        .first()
                        .leafCertificate
                        .serialize()
                        .asList(),
                )
                assertEquals(
                    chain.map { it.serialize().asList() },
                    result.first().certificateAuthorities.map { it.serialize().asList() },
                )

                val resultDiff = keystore.retrieveAll(subjectId, issuerId + "diff")
                assertEquals(1, resultDiff.size)
                assertEquals(
                    certificate.serialize().asList(),
                    resultDiff
                        .first()
                        .leafCertificate
                        .serialize()
                        .asList(),
                )
                assertTrue(
                    resultDiff.first().certificateAuthorities.isEmpty(),
                )
            }

        @Test
        @DisabledOnOs(OS.WINDOWS)
        fun `Errors creating address subdirectory should be wrapped`() =
            runTest {
                keystoreRoot.directory.setExecutable(false)
                keystoreRoot.directory.setWritable(false)
                val keystore = FileCertificateStore(keystoreRoot)

                val exception =
                    assertThrows<FileKeystoreException> {
                        keystore.save(CertificationPath(certificate, chain), issuerId)
                    }

                assertEquals(
                    "Failed to create address directory for certification files",
                    exception.message,
                )
            }

        @Test
        @DisabledOnOs(OS.WINDOWS)
        fun `Errors creating or updating file should be wrapped`() =
            runTest {
                subjectFolder.mkdirs()
                subjectFolder.setWritable(false)
                val keystore = FileCertificateStore(keystoreRoot)

                val exception =
                    assertThrows<FileKeystoreException> {
                        keystore.save(CertificationPath(certificate, chain), issuerId)
                    }

                assertEquals("Failed to save certification file", exception.message)
                assertTrue(exception.cause is IOException)
            }
    }

    @Nested
    inner class RetrieveData {
        @Test
        fun `All valid certificates should be retrieved`() =
            runTest {
                val keystore = FileCertificateStore(keystoreRoot)

                keystore.save(CertificationPath(certificate, chain), issuerId)
                keystore.save(CertificationPath(longerCertificate, chain), issuerId)
                keystore.save(CertificationPath(aboutToExpireCertificate, chain), issuerId)

                Thread.sleep(300) // wait for aboutToExpireCertificate to expire

                val result = keystore.retrieveAll(subjectId, issuerId)
                assertEquals(2, result.size)
                assertTrue(
                    result.any { certPath ->
                        certificate.serialize().asList() ==
                            certPath.leafCertificate.serialize().asList() &&
                            chain.map { it.serialize().asList() } ==
                            certPath.certificateAuthorities.map { it.serialize().asList() }
                    },
                )

                assertTrue(
                    result.any { certPath ->
                        longerCertificate.serialize().asList() ==
                            certPath.leafCertificate.serialize().asList() &&
                            chain.map { it.serialize().asList() } ==
                            certPath.certificateAuthorities.map { it.serialize().asList() }
                    },
                )
            }

        @Test
        fun `Certificates should not be retrieved with wrong issuer`() =
            runTest {
                val keystore = FileCertificateStore(keystoreRoot)

                keystore.save(CertificationPath(certificate, chain), issuerId)

                val result = keystore.retrieveAll(subjectId, "wrong")
                assertTrue(result.isEmpty())
            }

        @Test
        fun `If there are no certificates return empty list`() =
            runTest {
                val keystore = FileCertificateStore(keystoreRoot)

                val result = keystore.retrieveAll(subjectId, issuerId)
                assertTrue(result.isEmpty())
            }

        @Test
        @DisabledOnOs(OS.WINDOWS) // Windows can't tell apart between not-readable and non-existing
        fun `If there is a non-readable certificate file throw FileKeystoreException`() =
            runTest {
                val keystore = FileCertificateStore(keystoreRoot)

                val timestamp = Instant.now().plusSeconds(1).toEpochMilli()
                subjectFolder.mkdirs()
                val file = subjectFolder.resolve("$timestamp-12345")
                file.createNewFile()
                file.setReadable(false)

                val exception =
                    assertThrows<FileKeystoreException> {
                        keystore.retrieveAll(subjectId, issuerId)
                    }
                assertEquals(
                    "Failed to read certification file",
                    exception.message,
                )
            }

        @Test
        fun `If there is an invalid certificate file name throw FileKeystoreException`() =
            runTest {
                val keystore = FileCertificateStore(keystoreRoot)

                subjectFolder.mkdirs()
                subjectFolder.resolve("INVALID").createNewFile()

                val exception =
                    assertThrows<FileKeystoreException> {
                        keystore.retrieveAll(subjectId, issuerId)
                    }
                assertEquals(
                    "Invalid certificate file name: INVALID",
                    exception.message,
                )
            }

        @Test
        fun `If there is a certificate file name with invalid timestamp throw exception`() =
            runTest {
                val keystore = FileCertificateStore(keystoreRoot)

                subjectFolder.mkdirs()
                subjectFolder.resolve("AAA-AAA").createNewFile()

                val exception =
                    assertThrows<FileKeystoreException> {
                        keystore.retrieveAll(subjectId, issuerId)
                    }
                assertEquals(
                    "Invalid certificate file name: AAA-AAA",
                    exception.message,
                )
            }
    }

    @Nested
    inner class DeleteExpired {
        @Test
        fun `Certificates that are expired are deleted`() =
            runTest {
                val keystore = FileCertificateStore(keystoreRoot)

                keystore.save(CertificationPath(certificate, chain), issuerId)
                // create empty expired cert file
                subjectFolder.resolve("0-12345").createNewFile()

                assertEquals(2, subjectFolder.listFiles()!!.size)

                keystore.deleteExpired()

                assertEquals(1, subjectFolder.listFiles()!!.size)
            }

        @Test
        fun `Skip if root folder couldn't be read`() =
            runTest {
                val keystore = FileCertificateStore(keystoreRoot)

                storeRootFile.setReadable(false)

                keystore.deleteExpired()
                storeRootFile.setReadable(true)
            }

        @Test
        fun `Skip if issuer folder couldn't be read`() =
            runTest {
                val keystore = FileCertificateStore(keystoreRoot)

                issuerFolder.mkdirs()
                issuerFolder.setReadable(false)

                keystore.deleteExpired()
                issuerFolder.setReadable(true)
            }

        @Test
        fun `Skip if address folder couldn't be read`() =
            runTest {
                val keystore = FileCertificateStore(keystoreRoot)

                subjectFolder.mkdirs()
                subjectFolder.setReadable(false)

                keystore.deleteExpired()
                subjectFolder.setReadable(true)
            }

        @Test
        fun `Skip files inside root folder`() =
            runTest {
                val keystore = FileCertificateStore(keystoreRoot)

                storeRootFile.mkdirs()
                storeRootFile.resolve("file").createNewFile()

                keystore.deleteExpired()
            }

        @Test
        fun `Skip files inside issuer folder`() =
            runTest {
                val keystore = FileCertificateStore(keystoreRoot)

                issuerFolder.mkdirs()
                issuerFolder.resolve("file").createNewFile()

                keystore.deleteExpired()
            }

        @Test
        fun `Skip if expired certificate couldn't be deleted`() =
            runTest {
                val keystore = FileCertificateStore(keystoreRoot)

                subjectFolder.mkdirs()
                val file = subjectFolder.resolve("0-12345")
                file.createNewFile()
                storeRootFile.setWritable(false)

                keystore.deleteExpired()
            }
    }

    @Nested
    inner class Delete {
        @Test
        fun `Certificates of given subject and issuer addresses are deleted`() =
            runTest {
                val keystore = FileCertificateStore(keystoreRoot)

                keystore.save(CertificationPath(certificate, chain), issuerId)
                keystore.save(CertificationPath(unrelatedCertificate, chain), issuerId)
                keystore.save(CertificationPath(certificate, chain), issuerId + "diff")

                assertEquals(
                    1,
                    keystore.retrieveAll(certificate.subjectId, issuerId).size,
                )
                assertEquals(
                    1,
                    keystore.retrieveAll(unrelatedCertificate.subjectId, issuerId).size,
                )
                assertEquals(
                    1,
                    keystore.retrieveAll(certificate.subjectId, issuerId + "diff").size,
                )

                keystore.delete(certificate.subjectId, issuerId)

                assertEquals(
                    0,
                    keystore.retrieveAll(certificate.subjectId, issuerId).size,
                )
                assertEquals(
                    1,
                    keystore.retrieveAll(unrelatedCertificate.subjectId, issuerId).size,
                )
                assertEquals(
                    1,
                    keystore.retrieveAll(certificate.subjectId, issuerId + "diff").size,
                )
            }

        @Test
        @DisabledOnOs(OS.WINDOWS) // Windows can't tell apart between not-writable and non-existing
        fun `Exception should be thrown if address directory couldn't be deleted`() =
            runTest {
                val keystore = FileCertificateStore(keystoreRoot)

                subjectFolder.mkdirs()
                issuerFolder.setWritable(false)

                val exception =
                    assertThrows<FileKeystoreException> {
                        keystore.delete(subjectId, issuerId)
                    }
                assertEquals(
                    "Failed to delete node directory for $subjectId",
                    exception.message,
                )
            }

        @Test
        fun `Nothing should happen to unrelated certificates if deleting non-existing address`() =
            runTest {
                val keystore = FileCertificateStore(keystoreRoot)

                keystore.save(CertificationPath(certificate, chain), issuerId)
                keystore.delete("unrelated", issuerId)

                assertEquals(
                    1,
                    keystore.retrieveAll(certificate.subjectId, issuerId).size,
                )
            }
    }
}
