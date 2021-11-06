package tech.relaycorp.awala.keystores.file

import java.io.IOException
import java.nio.ByteBuffer
import java.nio.file.Path
import java.time.ZonedDateTime
import kotlin.io.path.createDirectories
import kotlin.io.path.exists
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runBlockingTest
import org.bson.BSONException
import org.bson.BsonBinary
import org.bson.BsonBinaryReader
import org.bson.BsonBinaryWriter
import org.bson.io.BasicOutputBuffer
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.condition.DisabledOnOs
import org.junit.jupiter.api.condition.OS
import tech.relaycorp.relaynet.SessionKeyPair
import tech.relaycorp.relaynet.issueEndpointCertificate
import tech.relaycorp.relaynet.keystores.MissingKeyException
import tech.relaycorp.relaynet.testing.pki.KeyPairSet
import tech.relaycorp.relaynet.testing.pki.PDACertPath

@ExperimentalCoroutinesApi
@Suppress("BlockingMethodInNonBlockingContext")
class FilePrivateKeyStoreTest : KeystoreTestCase() {
    private val certificate = PDACertPath.PRIVATE_ENDPOINT
    private val privateKey = KeyPairSet.PRIVATE_ENDPOINT.private
    private val privateAddress = certificate.subjectPrivateAddress
    private val sessionKeypair = SessionKeyPair.generate()

    private val peerPrivateAddress = PDACertPath.PDA.subjectPrivateAddress

    private val privateKeystoreRootPath = keystoreRoot.directory.resolve("private")
    private val nodeDirectoryPath = privateKeystoreRootPath.resolve(privateAddress)

    private val identityKeyFilePath = nodeDirectoryPath.resolve("i-$privateAddress")
    private val sessionKeyFilePath = nodeDirectoryPath.resolve(
        "s-${byteArrayToHex(sessionKeypair.sessionKey.keyId)}"
    )

    @Nested
    inner class Save {
        @Test
        fun `Node subdirectory should be reused if it already exists`() = runBlockingTest {
            nodeDirectoryPath.createDirectories()
            val keystore = MockFilePrivateKeyStore(keystoreRoot)

            keystore.saveIdentityKey(privateKey, certificate)

            assertTrue(identityKeyFilePath.exists(), "$identityKeyFilePath must exist")
        }

        @Test
        fun `Root directory should be created if it doesn't already exist`() = runBlockingTest {
            assertFalse(privateKeystoreRootPath.exists())
            val keystore = MockFilePrivateKeyStore(keystoreRoot)

            keystore.saveIdentityKey(privateKey, certificate)

            assertTrue(identityKeyFilePath.exists())
        }

        @Test
        fun `Node subdirectory should be created if it doesn't already exist`() = runBlockingTest {
            assertFalse(nodeDirectoryPath.exists())
            val keystore = MockFilePrivateKeyStore(keystoreRoot)

            keystore.saveIdentityKey(privateKey, certificate)

            assertTrue(identityKeyFilePath.exists())
        }

        @Test
        fun `New file should be created if key is new`() = runBlockingTest {
            assertFalse(identityKeyFilePath.exists())
            val keystore = MockFilePrivateKeyStore(keystoreRoot)

            keystore.saveIdentityKey(privateKey, certificate)

            assertTrue(identityKeyFilePath.exists())
        }

        @Test
        fun `Private key should be stored`() = runBlockingTest {
            val keystore = MockFilePrivateKeyStore(keystoreRoot)

            keystore.saveIdentityKey(privateKey, certificate)

            val savedKeyData = readKeyData(identityKeyFilePath)
            assertEquals(
                privateKey.encoded.asList(),
                savedKeyData.readBinaryData("private_key").data.asList()
            )
        }

        @Test
        fun `Existing file should be updated if key already existed`() = runBlockingTest {
            val keystore = MockFilePrivateKeyStore(keystoreRoot)
            keystore.saveIdentityKey(privateKey, certificate)

            // Replace the certificate
            val differentCertificate = issueEndpointCertificate(
                KeyPairSet.PRIVATE_ENDPOINT.public,
                privateKey,
                ZonedDateTime.now().plusMinutes(1)
            )
            keystore.saveIdentityKey(privateKey, differentCertificate)

            val savedKeyData = readKeyData(identityKeyFilePath)
            savedKeyData.readBinaryData("private_key")
            assertEquals(
                differentCertificate.serialize().asList(),
                savedKeyData.readBinaryData("certificate").data.asList()
            )
        }

        @Test
        fun `Certificate should be stored if it was present`() = runBlockingTest {
            val keystore = MockFilePrivateKeyStore(keystoreRoot)

            keystore.saveIdentityKey(privateKey, certificate)

            val savedKeyData = readKeyData(identityKeyFilePath)
            savedKeyData.readBinaryData("private_key")
            assertEquals(
                certificate.serialize().asList(),
                savedKeyData.readBinaryData("certificate").data.asList()
            )
        }

        @Test
        fun `No certificate should be stored if it was absent`() = runBlockingTest {
            val keystore = MockFilePrivateKeyStore(keystoreRoot)

            keystore.saveSessionKey(
                sessionKeypair.privateKey,
                sessionKeypair.sessionKey.keyId,
                privateAddress
            )

            val savedKeyData = readKeyData(sessionKeyFilePath)
            savedKeyData.readBinaryData("private_key")
            assertEquals(0, savedKeyData.readBinaryData("certificate").data.size)
        }

        @Test
        fun `Peer private address should be stored if it was present`() = runBlockingTest {
            val keystore = MockFilePrivateKeyStore(keystoreRoot)

            keystore.saveSessionKey(
                sessionKeypair.privateKey,
                sessionKeypair.sessionKey.keyId,
                privateAddress,
                peerPrivateAddress,
            )

            val savedKeyData = readKeyData(sessionKeyFilePath)
            savedKeyData.readBinaryData("private_key")
            savedKeyData.readBinaryData("certificate")
            assertEquals(peerPrivateAddress, savedKeyData.readString("peer_private_address"))
        }

        @Test
        fun `No peer private address should be stored if it was absent`() = runBlockingTest {
            val keystore = MockFilePrivateKeyStore(keystoreRoot)

            keystore.saveSessionKey(
                sessionKeypair.privateKey,
                sessionKeypair.sessionKey.keyId,
                privateAddress
            )

            val savedKeyData = readKeyData(sessionKeyFilePath)
            savedKeyData.readBinaryData("private_key")
            savedKeyData.readBinaryData("certificate")
            assertEquals("", savedKeyData.readString("peer_private_address"))
        }

        @Test
        @DisabledOnOs(OS.WINDOWS)
        fun `Errors creating node subdirectory should be wrapped`() = runBlockingTest {
            keystoreRoot.directory.toFile().setExecutable(false)
            keystoreRoot.directory.toFile().setWritable(false)
            val keystore = MockFilePrivateKeyStore(keystoreRoot)

            val exception = assertThrows<FileKeystoreException> {
                keystore.saveIdentityKey(privateKey, certificate)
            }

            assertEquals(
                "Failed to create root directory for private keys",
                exception.message
            )
            assertTrue(exception.cause is IOException)
        }

        @Test
        @DisabledOnOs(OS.WINDOWS)
        fun `Errors creating or updating file should be wrapped`() = runBlockingTest {
            nodeDirectoryPath.createDirectories()
            identityKeyFilePath.toFile().createNewFile()
            identityKeyFilePath.toFile().setWritable(false)
            val keystore = MockFilePrivateKeyStore(keystoreRoot)

            val exception = assertThrows<FileKeystoreException> {
                keystore.saveIdentityKey(privateKey, certificate)
            }

            assertEquals("Failed to save key file", exception.message)
            assertTrue(exception.cause is IOException)
        }

        private fun readKeyData(path: Path) = BsonBinaryReader(
            ByteBuffer.wrap(MockFilePrivateKeyStore.readFile(path.toFile()))
        ).also {
            it.readStartDocument()
        }
    }

    @Nested
    inner class Retrieve {
        @Test
        fun `Key should be reported as missing if the directory doesn't exist`() = runBlockingTest {
            assertFalse(nodeDirectoryPath.exists())
            val keystore = MockFilePrivateKeyStore(keystoreRoot)

            assertThrows<MissingKeyException> { keystore.retrieveIdentityKey(privateAddress) }
        }

        @Test
        fun `Key should be reported as missing if the file doesn't exist`() = runBlockingTest {
            nodeDirectoryPath.createDirectories()
            val keystore = MockFilePrivateKeyStore(keystoreRoot)

            assertThrows<MissingKeyException> { keystore.retrieveIdentityKey(privateAddress) }
        }

        @Test
        @DisabledOnOs(OS.WINDOWS) // Windows can't tell apart between not-readable and non-existing
        fun `Exception should be thrown if file isn't readable`() = runBlockingTest {
            saveKeyData(identityKeyFilePath) {}
            identityKeyFilePath.toFile().setReadable(false)
            val keystore = MockFilePrivateKeyStore(keystoreRoot)

            val exception = assertThrows<FileKeystoreException> {
                keystore.retrieveIdentityKey(privateAddress)
            }

            assertEquals("Failed to read key file", exception.message)
            assertTrue(exception.cause is IOException)
        }

        @Test
        fun `Exception should be thrown if file is not BSON-serialized`() = runBlockingTest {
            nodeDirectoryPath.createDirectories()
            identityKeyFilePath.toFile().writeBytes("Not BSON".toByteArray())
            val keystore = MockFilePrivateKeyStore(keystoreRoot)

            val exception = assertThrows<FileKeystoreException> {
                keystore.retrieveIdentityKey(privateAddress)
            }

            assertEquals("Key file is malformed", exception.message)
            assertTrue(exception.cause is BSONException)
        }

        @Test
        fun `Exception should be thrown if private key is missing`() = runBlockingTest {
            saveKeyData(identityKeyFilePath) {
                writeBinaryData("certificate", BsonBinary(certificate.serialize()))
                writeString("peer_private_address", privateAddress)
            }
            val keystore = MockFilePrivateKeyStore(keystoreRoot)

            val exception = assertThrows<FileKeystoreException> {
                keystore.retrieveIdentityKey(privateAddress)
            }

            assertEquals("Key file is malformed", exception.message)
            assertTrue(exception.cause is BSONException)
        }

        @Test
        fun `Private key should be returned if file exists and is valid`() = runBlockingTest {
            val keystore = MockFilePrivateKeyStore(keystoreRoot)
            keystore.saveIdentityKey(privateKey, certificate)

            val key = keystore.retrieveIdentityKey(privateAddress)

            assertEquals(privateKey, key.privateKey)
        }

        @Test
        fun `Certificate should be returned if present`() = runBlockingTest {
            val keystore = MockFilePrivateKeyStore(keystoreRoot)
            keystore.saveIdentityKey(privateKey, certificate)

            val key = keystore.retrieveIdentityKey(privateAddress)

            assertEquals(certificate, key.certificate)
        }

        @Test
        fun `Certificate should not be returned if absent`() = runBlockingTest {
            saveKeyData(identityKeyFilePath) {
                writeBinaryData("private_key", BsonBinary(privateKey.encoded))
                writeString("peer_private_address", privateAddress)
            }
            val keystore = MockFilePrivateKeyStore(keystoreRoot)

            val exception = assertThrows<FileKeystoreException> {
                keystore.retrieveIdentityKey(privateAddress)
            }

            assertEquals("Key file is malformed", exception.message)
            assertTrue(exception.cause is BSONException)
        }

        @Test
        fun `Peer private address should be returned if present`() = runBlockingTest {
            val keystore = MockFilePrivateKeyStore(keystoreRoot)
            keystore.saveSessionKey(
                sessionKeypair.privateKey,
                sessionKeypair.sessionKey.keyId,
                privateAddress,
                peerPrivateAddress
            )

            // Check that the key is bound to the peer
            keystore.retrieveSessionKey(
                sessionKeypair.sessionKey.keyId,
                privateAddress,
                peerPrivateAddress
            )
            assertThrows<MissingKeyException> {
                keystore.retrieveSessionKey(
                    sessionKeypair.sessionKey.keyId,
                    privateAddress,
                    "not $peerPrivateAddress"
                )
            }
        }

        @Test
        fun `Peer private address should not be returned if absent`() = runBlockingTest {
            val keystore = MockFilePrivateKeyStore(keystoreRoot)
            keystore.saveSessionKey(
                sessionKeypair.privateKey,
                sessionKeypair.sessionKey.keyId,
                privateAddress,
            )

            // Check that the key is unbound
            keystore.retrieveSessionKey(
                sessionKeypair.sessionKey.keyId,
                privateAddress,
                peerPrivateAddress
            )
            keystore.retrieveSessionKey(
                sessionKeypair.sessionKey.keyId,
                privateAddress,
                "not $peerPrivateAddress"
            )
        }

        private fun saveKeyData(path: Path, writeBsonFields: BsonBinaryWriter.() -> Unit) {
            if (!nodeDirectoryPath.exists()) {
                nodeDirectoryPath.createDirectories()
            }
            val bsonSerialization = BasicOutputBuffer().use { buffer ->
                BsonBinaryWriter(buffer).use {
                    it.writeStartDocument()
                    writeBsonFields(it)
                    it.writeEndDocument()
                }
                buffer.toByteArray()
            }
            MockFilePrivateKeyStore.writeFile(path.toFile(), bsonSerialization)
        }
    }

    private fun byteArrayToHex(byteArray: ByteArray) =
        byteArray.joinToString("") { "%02x".format(it) }
}