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

    private val certificate = issueGatewayCertificate(
        KeyPairSet.PRIVATE_GW.public,
        KeyPairSet.PUBLIC_GW.private,
        validityEndDate = ZonedDateTime.now().plusHours(1),
        validityStartDate = ZonedDateTime.now().minusSeconds(1)
    )
    private val chain = listOf(PDACertPath.PUBLIC_GW)
    private val issuerAddress = PDACertPath.PUBLIC_GW.subjectPrivateAddress
    private val address = certificate.subjectPrivateAddress
    private val issuerFolder = storeRootFile.resolve(issuerAddress)
    private val addressFolder = issuerFolder.resolve(address)

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
    private val unrelatedCertificate = PDACertPath.PRIVATE_ENDPOINT

    @Test
    fun `Root directory should be exposed`() {
        val keystore = FileCertificateStore(keystoreRoot)

        assertEquals(storeRootFile, keystore.rootDirectory)
    }

    @Nested
    inner class SaveData {
        @Test
        fun `Certificate should be stored and retrieved`() = runTest {
            val keystore = FileCertificateStore(keystoreRoot)

            keystore.save(CertificationPath(certificate, chain), issuerAddress)

            val result = keystore.retrieveAll(address, issuerAddress)
            assertEquals(1, result.size)
            assertEquals(
                certificate.serialize().asList(),
                result.first().leafCertificate.serialize().asList()
            )
            assertEquals(
                chain.map { it.serialize().asList() },
                result.first().certificateAuthorities.map { it.serialize().asList() }
            )

            val addressFiles = addressFolder.listFiles()!!
            assertEquals(1, addressFiles.size)
            with(addressFiles.first()) {
                assertTrue(exists())
                assertTrue(
                    name.startsWith("${certificate.expiryDate.toInstant().toEpochMilli()}-")
                )
            }
        }

        @Test
        fun `Certificate stored multiple times should override`() = runTest {
            val keystore = FileCertificateStore(keystoreRoot)

            repeat(3) {
                keystore.save(CertificationPath(certificate, chain), issuerAddress)
            }

            val result = keystore.retrieveAll(address, issuerAddress)
            assertEquals(1, result.size)
            assertEquals(
                certificate.serialize().asList(),
                result.first().leafCertificate.serialize().asList()
            )
            assertEquals(
                chain.map { it.serialize().asList() },
                result.first().certificateAuthorities.map { it.serialize().asList() }
            )

            val addressFiles = addressFolder.listFiles()!!
            assertEquals(1, addressFiles.size)
        }

        @Test
        internal fun `Certificates by different issuers should not override`() = runTest {
            val keystore = FileCertificateStore(keystoreRoot)

            keystore.save(CertificationPath(certificate, chain), issuerAddress)
            keystore.save(CertificationPath(certificate, emptyList()), issuerAddress + "diff")

            val result = keystore.retrieveAll(address, issuerAddress)
            assertEquals(1, result.size)
            assertEquals(
                certificate.serialize().asList(),
                result.first().leafCertificate.serialize().asList()
            )
            assertEquals(
                chain.map { it.serialize().asList() },
                result.first().certificateAuthorities.map { it.serialize().asList() }
            )

            val resultDiff = keystore.retrieveAll(address, issuerAddress + "diff")
            assertEquals(1, resultDiff.size)
            assertEquals(
                certificate.serialize().asList(),
                resultDiff.first().leafCertificate.serialize().asList()
            )
            assertTrue(
                resultDiff.first().certificateAuthorities.isEmpty()
            )
        }

        @Test
        @DisabledOnOs(OS.WINDOWS)
        fun `Errors creating address subdirectory should be wrapped`() = runTest {
            keystoreRoot.directory.setExecutable(false)
            keystoreRoot.directory.setWritable(false)
            val keystore = FileCertificateStore(keystoreRoot)

            val exception = assertThrows<FileKeystoreException> {
                keystore.save(CertificationPath(certificate, chain), issuerAddress)
            }

            assertEquals(
                "Failed to create address directory for certification files",
                exception.message
            )
        }

        @Test
        @DisabledOnOs(OS.WINDOWS)
        fun `Errors creating or updating file should be wrapped`() = runTest {
            addressFolder.mkdirs()
            addressFolder.setWritable(false)
            val keystore = FileCertificateStore(keystoreRoot)

            val exception = assertThrows<FileKeystoreException> {
                keystore.save(CertificationPath(certificate, chain), issuerAddress)
            }

            assertEquals("Failed to save certification file", exception.message)
            assertTrue(exception.cause is IOException)
        }
    }

    @Nested
    inner class RetrieveData {

        @Test
        fun `All valid certificates should be retrieved`() = runTest {
            val keystore = FileCertificateStore(keystoreRoot)

            keystore.save(CertificationPath(certificate, chain), issuerAddress)
            keystore.save(CertificationPath(longerCertificate, chain), issuerAddress)
            keystore.save(CertificationPath(aboutToExpireCertificate, chain), issuerAddress)

            Thread.sleep(300) // wait for aboutToExpireCertificate to expire

            val result = keystore.retrieveAll(address, issuerAddress)
            assertEquals(2, result.size)
            assertTrue(
                result.any { certPath ->
                    certificate.serialize().asList() ==
                        certPath.leafCertificate.serialize().asList() &&
                        chain.map { it.serialize().asList() } ==
                        certPath.certificateAuthorities.map { it.serialize().asList() }
                }
            )

            assertTrue(
                result.any { certPath ->
                    longerCertificate.serialize().asList() ==
                        certPath.leafCertificate.serialize().asList() &&
                        chain.map { it.serialize().asList() } ==
                        certPath.certificateAuthorities.map { it.serialize().asList() }
                }
            )
        }

        @Test
        fun `Certificates should not be retrieved with wrong issuer`() = runTest {
            val keystore = FileCertificateStore(keystoreRoot)

            keystore.save(CertificationPath(certificate, chain), issuerAddress)

            val result = keystore.retrieveAll(address, "wrong")
            assertTrue(result.isEmpty())
        }

        @Test
        fun `If there are no certificates return empty list`() = runTest {
            val keystore = FileCertificateStore(keystoreRoot)

            val result = keystore.retrieveAll(address, issuerAddress)
            assertTrue(result.isEmpty())
        }

        @Test
        @DisabledOnOs(OS.WINDOWS) // Windows can't tell apart between not-readable and non-existing
        fun `If there is a non-readable certificate file throw FileKeystoreException`() =
            runTest {
                val keystore = FileCertificateStore(keystoreRoot)

                val timestamp = Instant.now().plusSeconds(1).toEpochMilli()
                addressFolder.mkdirs()
                val file = addressFolder.resolve("$timestamp-12345")
                file.createNewFile()
                file.setReadable(false)

                val exception = assertThrows<FileKeystoreException> {
                    keystore.retrieveAll(address, issuerAddress)
                }
                assertEquals(
                    "Failed to read certification file",
                    exception.message
                )
            }

        @Test
        fun `If there is an invalid certificate file name throw FileKeystoreException`() =
            runTest {
                val keystore = FileCertificateStore(keystoreRoot)

                addressFolder.mkdirs()
                addressFolder.resolve("INVALID").createNewFile()

                val exception = assertThrows<FileKeystoreException> {
                    keystore.retrieveAll(address, issuerAddress)
                }
                assertEquals(
                    "Invalid certificate file name: INVALID",
                    exception.message
                )
            }

        @Test
        fun `If there is a certificate file name with invalid timestamp throw exception`() =
            runTest {
                val keystore = FileCertificateStore(keystoreRoot)

                addressFolder.mkdirs()
                addressFolder.resolve("AAA-AAA").createNewFile()

                val exception = assertThrows<FileKeystoreException> {
                    keystore.retrieveAll(address, issuerAddress)
                }
                assertEquals(
                    "Invalid certificate file name: AAA-AAA",
                    exception.message
                )
            }
    }

    @Nested
    inner class DeleteExpired {

        @Test
        fun `Certificates that are expired are deleted`() = runTest {
            val keystore = FileCertificateStore(keystoreRoot)

            keystore.save(CertificationPath(certificate, chain), issuerAddress)
            // create empty expired cert file
            addressFolder.resolve("0-12345").createNewFile()

            assertEquals(2, addressFolder.listFiles()!!.size)

            keystore.deleteExpired()

            assertEquals(1, addressFolder.listFiles()!!.size)
        }

        @Test
        fun `Skip if root folder couldn't be read`() = runTest {
            val keystore = FileCertificateStore(keystoreRoot)

            storeRootFile.setReadable(false)

            keystore.deleteExpired()
            storeRootFile.setReadable(true)
        }

        @Test
        fun `Skip if issuer folder couldn't be read`() = runTest {
            val keystore = FileCertificateStore(keystoreRoot)

            issuerFolder.mkdirs()
            issuerFolder.setReadable(false)

            keystore.deleteExpired()
            issuerFolder.setReadable(true)
        }

        @Test
        fun `Skip if address folder couldn't be read`() = runTest {
            val keystore = FileCertificateStore(keystoreRoot)

            addressFolder.mkdirs()
            addressFolder.setReadable(false)

            keystore.deleteExpired()
            addressFolder.setReadable(true)
        }

        @Test
        fun `Skip files inside root folder`() = runTest {
            val keystore = FileCertificateStore(keystoreRoot)

            storeRootFile.mkdirs()
            storeRootFile.resolve("file").createNewFile()

            keystore.deleteExpired()
        }

        @Test
        fun `Skip files inside issuer folder`() = runTest {
            val keystore = FileCertificateStore(keystoreRoot)

            issuerFolder.mkdirs()
            issuerFolder.resolve("file").createNewFile()

            keystore.deleteExpired()
        }

        @Test
        fun `Skip if expired certificate couldn't be deleted`() = runTest {
            val keystore = FileCertificateStore(keystoreRoot)

            addressFolder.mkdirs()
            val file = addressFolder.resolve("0-12345")
            file.createNewFile()
            storeRootFile.setWritable(false)

            keystore.deleteExpired()
        }
    }

    @Nested
    inner class Delete {

        @Test
        fun `Certificates of given subject and issuer addresses are deleted`() = runTest {
            val keystore = FileCertificateStore(keystoreRoot)

            keystore.save(CertificationPath(certificate, chain), issuerAddress)
            keystore.save(CertificationPath(unrelatedCertificate, chain), issuerAddress)
            keystore.save(CertificationPath(certificate, chain), issuerAddress + "diff")

            assertEquals(
                1,
                keystore.retrieveAll(certificate.subjectPrivateAddress, issuerAddress).size
            )
            assertEquals(
                1,
                keystore.retrieveAll(unrelatedCertificate.subjectPrivateAddress, issuerAddress).size
            )
            assertEquals(
                1,
                keystore.retrieveAll(certificate.subjectPrivateAddress, issuerAddress + "diff").size
            )

            keystore.delete(certificate.subjectPrivateAddress, issuerAddress)

            assertEquals(
                0,
                keystore.retrieveAll(certificate.subjectPrivateAddress, issuerAddress).size
            )
            assertEquals(
                1,
                keystore.retrieveAll(unrelatedCertificate.subjectPrivateAddress, issuerAddress).size
            )
            assertEquals(
                1,
                keystore.retrieveAll(certificate.subjectPrivateAddress, issuerAddress + "diff").size
            )
        }

        @Test
        @DisabledOnOs(OS.WINDOWS) // Windows can't tell apart between not-writable and non-existing
        fun `Exception should be thrown if address directory couldn't be deleted`() =
            runTest {
                val keystore = FileCertificateStore(keystoreRoot)

                addressFolder.mkdirs()
                issuerFolder.setWritable(false)

                val exception = assertThrows<FileKeystoreException> {
                    keystore.delete(address, issuerAddress)
                }
                assertEquals(
                    "Failed to delete node directory for $address",
                    exception.message
                )
            }

        @Test
        fun `Nothing should happen to unrelated certificates if deleting non-existing address`() =
            runTest {
                val keystore = FileCertificateStore(keystoreRoot)

                keystore.save(CertificationPath(certificate, chain), issuerAddress)
                keystore.delete("unrelated", issuerAddress)

                assertEquals(
                    1,
                    keystore.retrieveAll(certificate.subjectPrivateAddress, issuerAddress).size
                )
            }
    }
}
