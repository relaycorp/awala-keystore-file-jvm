package tech.relaycorp.awala.keystores.file

import java.io.IOException
import java.time.Instant
import java.time.ZonedDateTime
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runBlockingTest
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.condition.DisabledOnOs
import org.junit.jupiter.api.condition.OS
import tech.relaycorp.relaynet.issueGatewayCertificate
import tech.relaycorp.relaynet.testing.pki.KeyPairSet
import tech.relaycorp.relaynet.testing.pki.PDACertPath

@ExperimentalCoroutinesApi
@Suppress("BlockingMethodInNonBlockingContext")
class FileCertificateStoreTest : KeystoreTestCase() {

    private val storeRootFile = keystoreRoot.directory.resolve("certificate")

    private val certificate = issueGatewayCertificate(
        KeyPairSet.PRIVATE_GW.public,
        KeyPairSet.PUBLIC_GW.private,
        validityEndDate = ZonedDateTime.now().plusHours(1),
        validityStartDate = ZonedDateTime.now().minusSeconds(1)
    )
    private val chain = listOf(PDACertPath.PUBLIC_GW)
    private val address = certificate.subjectPrivateAddress
    private val addressFolder = storeRootFile.resolve(address)

    private val longerCertificate = issueGatewayCertificate(
        KeyPairSet.PRIVATE_GW.public,
        KeyPairSet.PUBLIC_GW.private,
        validityEndDate = ZonedDateTime.now().plusHours(10),
        validityStartDate = ZonedDateTime.now().minusSeconds(1)
    )
    private val aboutToExpireCertificate = issueGatewayCertificate(
        KeyPairSet.PRIVATE_GW.public,
        KeyPairSet.PUBLIC_GW.private,
        validityEndDate = ZonedDateTime.now().plusNanos(100_000_000),
        validityStartDate = ZonedDateTime.now().minusSeconds(1)
    )
    private val unrelatedCertificate = PDACertPath.PUBLIC_GW

    @Test
    fun `Root directory should be exposed`() {
        val keystore = MockFileCertificateStore(keystoreRoot)

        assertEquals(storeRootFile, keystore.rootDirectory)
    }

    @Nested
    inner class SaveData {
        @Test
        fun `Certificate should be stored and retrieved`() = runBlockingTest {
            val keystore = MockFileCertificateStore(keystoreRoot)

            keystore.save(certificate, chain)

            val result = keystore.retrieveAll(address)
            assertEquals(1, result.size)
            assertEquals(
                certificate.serialize().asList(),
                result.first().leafCertificate.serialize().asList()
            )
            assertEquals(
                chain.map { it.serialize().asList() },
                result.first().chain.map { it.serialize().asList() }
            )

            val addressFiles = addressFolder.listFiles()!!
            assertEquals(1, addressFiles.size)
            with(addressFiles.first()) {
                assertTrue(exists())
                assertTrue(
                    name.startsWith("CERT-${certificate.expiryDate.toInstant().toEpochMilli()}-")
                )
            }
        }

        @Test
        fun `Certificate stored multiple times should override`() = runBlockingTest {
            val keystore = MockFileCertificateStore(keystoreRoot)

            repeat(3) {
                keystore.save(certificate, chain)
            }

            val result = keystore.retrieveAll(address)
            assertEquals(1, result.size)
            assertEquals(
                certificate.serialize().asList(),
                result.first().leafCertificate.serialize().asList()
            )
            assertEquals(
                chain.map { it.serialize().asList() },
                result.first().chain.map { it.serialize().asList() }
            )

            val addressFiles = addressFolder.listFiles()!!
            assertEquals(1, addressFiles.size)
        }

        @Test
        @DisabledOnOs(OS.WINDOWS)
        fun `Errors creating address subdirectory should be wrapped`() = runBlockingTest {
            keystoreRoot.directory.setExecutable(false)
            keystoreRoot.directory.setWritable(false)
            val keystore = MockFileCertificateStore(keystoreRoot)

            val exception = assertThrows<FileKeystoreException> {
                keystore.save(certificate, chain)
            }

            assertEquals(
                "Failed to create address directory for certification files",
                exception.message
            )
        }

        @Test
        @DisabledOnOs(OS.WINDOWS)
        fun `Errors creating or updating file should be wrapped`() = runBlockingTest {
            addressFolder.mkdirs()
            addressFolder.setWritable(false)
            val keystore = MockFileCertificateStore(keystoreRoot)

            val exception = assertThrows<FileKeystoreException> {
                keystore.save(certificate, chain)
            }

            assertEquals("Failed to save certification file", exception.message)
            assertTrue(exception.cause is IOException)
        }
    }

    @Nested
    inner class RetrieveData {

        @Test
        fun `All valid certificates should be retrieved`() = runBlockingTest {
            val keystore = MockFileCertificateStore(keystoreRoot)

            keystore.save(certificate, chain)
            keystore.save(longerCertificate, chain)
            keystore.save(aboutToExpireCertificate, chain)

            Thread.sleep(300) // wait for aboutToExpireCertificate to expire

            val result = keystore.retrieveAll(address)
            assertEquals(2, result.size)
            assertTrue(
                result.any { certPath ->
                    certificate.serialize().asList() ==
                        certPath.leafCertificate.serialize().asList() &&
                        chain.map { it.serialize().asList() } ==
                        certPath.chain.map { it.serialize().asList() }
                }
            )

            assertTrue(
                result.any { certPath ->
                    longerCertificate.serialize().asList() ==
                        certPath.leafCertificate.serialize().asList() &&
                        chain.map { it.serialize().asList() } ==
                        certPath.chain.map { it.serialize().asList() }
                }
            )
        }

        @Test
        fun `If there are no certificates return empty list`() = runBlockingTest {
            val keystore = MockFileCertificateStore(keystoreRoot)

            val result = keystore.retrieveAll(address)
            assertTrue(result.isEmpty())
        }

        @Test
        fun `If there is a non-readable certificate file throw FileKeystoreException`() =
            runBlockingTest {
                val keystore = MockFileCertificateStore(keystoreRoot)

                val timestamp = Instant.now().plusSeconds(1).toEpochMilli()
                addressFolder.mkdirs()
                val file = addressFolder.resolve("CERT-$timestamp-12345")
                file.createNewFile()
                file.setReadable(false)

                val exception = assertThrows<FileKeystoreException> {
                    keystore.retrieveAll(address)
                }
                assertEquals(
                    "Failed to read certification file",
                    exception.message
                )
            }

        @Test
        fun `If there is an invalid certificate file name throw FileKeystoreException`() =
            runBlockingTest {
                val keystore = MockFileCertificateStore(keystoreRoot)

                addressFolder.mkdirs()
                addressFolder.resolve("INVALID").createNewFile()

                val exception = assertThrows<FileKeystoreException> {
                    keystore.retrieveAll(address)
                }
                assertEquals(
                    "Invalid certificate file name: INVALID",
                    exception.message
                )
            }

        @Test
        fun `If there is a certificate file name with invalid timestamp throw exception`() =
            runBlockingTest {
                val keystore = MockFileCertificateStore(keystoreRoot)

                addressFolder.mkdirs()
                addressFolder.resolve("CERT-AAA-AAA").createNewFile()

                val exception = assertThrows<FileKeystoreException> {
                    keystore.retrieveAll(address)
                }
                assertEquals(
                    "Invalid certificate file name: CERT-AAA-AAA",
                    exception.message
                )
            }
    }

    @Nested
    inner class DeleteExpired {

        @Test
        fun `Certificates that are expired are deleted`() = runBlockingTest {
            val keystore = MockFileCertificateStore(keystoreRoot)

            keystore.save(certificate, chain)
            // create empty expired cert file
            addressFolder.resolve("CERT-0-12345").createNewFile()

            assertEquals(2, addressFolder.listFiles()!!.size)

            keystore.deleteExpired()

            assertEquals(1, addressFolder.listFiles()!!.size)
        }

        @Test
        fun `Skip if root folder couldn't be read`() = runBlockingTest {
            val keystore = MockFileCertificateStore(keystoreRoot)

            storeRootFile.setReadable(false)

            keystore.deleteExpired()
            storeRootFile.setReadable(true)
        }

        @Test
        fun `Skip if address folder couldn't be read`() = runBlockingTest {
            val keystore = MockFileCertificateStore(keystoreRoot)

            addressFolder.mkdirs()
            addressFolder.setReadable(false)

            keystore.deleteExpired()
            addressFolder.setReadable(true)
        }

        @Test
        fun `Skip files inside root folder`() = runBlockingTest {
            val keystore = MockFileCertificateStore(keystoreRoot)

            storeRootFile.mkdirs()
            storeRootFile.resolve("file").createNewFile()

            keystore.deleteExpired()
        }

        @Test
        fun `Skip if expired certificate couldn't be deleted`() = runBlockingTest {
            val keystore = MockFileCertificateStore(keystoreRoot)

            addressFolder.mkdirs()
            val file = addressFolder.resolve("CERT-0-12345")
            file.createNewFile()
            storeRootFile.setWritable(false)

            keystore.deleteExpired()
        }
    }

    @Nested
    inner class Delete {

        @Test
        fun `Certificates of given address are deleted`() = runBlockingTest {
            val keystore = MockFileCertificateStore(keystoreRoot)

            keystore.save(certificate, chain)
            keystore.save(unrelatedCertificate, chain)

            assertEquals(
                1,
                keystore.retrieveAll(certificate.subjectPrivateAddress).size
            )
            assertEquals(
                1,
                keystore.retrieveAll(unrelatedCertificate.subjectPrivateAddress).size
            )

            keystore.delete(certificate.subjectPrivateAddress)

            assertEquals(
                0,
                keystore.retrieveAll(certificate.subjectPrivateAddress).size
            )
            assertEquals(
                1,
                keystore.retrieveAll(unrelatedCertificate.subjectPrivateAddress).size
            )
        }

        @Test
        fun `Exception should be thrown if address directory couldn't be deleted`() =
            runBlockingTest {
                val keystore = MockFileCertificateStore(keystoreRoot)

                addressFolder.mkdirs()
                storeRootFile.setWritable(false)

                val exception = assertThrows<FileKeystoreException> {
                    keystore.delete(address)
                }
                assertEquals(
                    "Failed to delete node directory for $address",
                    exception.message
                )
            }

        @Test
        fun `Nothing should happen to unrelated certificates if deleting non-existing address`() =
            runBlockingTest {
                val keystore = MockFileCertificateStore(keystoreRoot)

                keystore.save(certificate, chain)
                keystore.delete("unrelated")

                assertEquals(
                    1,
                    keystore.retrieveAll(certificate.subjectPrivateAddress).size
                )
            }
    }
}
