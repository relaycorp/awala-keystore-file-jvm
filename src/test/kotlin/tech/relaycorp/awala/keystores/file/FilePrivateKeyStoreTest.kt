package tech.relaycorp.awala.keystores.file

import java.io.IOException
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

    private val privateKeystoreRootFile = keystoreRoot.directory.resolve("private")
    private val nodeDirectoryPath = privateKeystoreRootFile.resolve(privateAddress).toPath()

    private val identityKeyFilePath = nodeDirectoryPath.resolve("IDENTITY")
    private val sessionKeyFilePath = nodeDirectoryPath.resolve(
        "s-${byteArrayToHex(sessionKeypair.sessionKey.keyId)}"
    )

    @Nested
    inner class SaveIdentity : PrivateKeyStoreSavingTestCase(
        keystoreRoot,
        identityKeyFilePath,
        { saveIdentityKey(privateKey, certificate) }
    ) {

        @Test
        override fun `Private key should be stored`() = runBlockingTest {
            val keystore = MockFilePrivateKeyStore(keystoreRoot)

            keystore.saveIdentityKey(privateKey, certificate)

            val savedKeyData = readKeyData(identityKeyFilePath)
            assertEquals(
                privateKey.encoded.asList(),
                savedKeyData.readBinaryData("private_key").data.asList()
            )
        }

        @Test
        override fun `Existing file should be updated if key already existed`() = runBlockingTest {
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
        fun `Certificate should be stored`() = runBlockingTest {
            val keystore = MockFilePrivateKeyStore(keystoreRoot)

            keystore.saveIdentityKey(privateKey, certificate)

            val savedKeyData = readKeyData(identityKeyFilePath)
            savedKeyData.readBinaryData("private_key")
            assertEquals(
                certificate.serialize().asList(),
                savedKeyData.readBinaryData("certificate").data.asList()
            )
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

    @Nested
    inner class SaveSession : PrivateKeyStoreSavingTestCase(
        keystoreRoot,
        sessionKeyFilePath,
        {
            saveSessionKey(
                sessionKeypair.privateKey,
                sessionKeypair.sessionKey.keyId,
                privateAddress
            )
        }
    ) {

        @Test
        override fun `Private key should be stored`() = runBlockingTest {
            val keystore = MockFilePrivateKeyStore(keystoreRoot)

            keystore.saveSessionKey(
                sessionKeypair.privateKey,
                sessionKeypair.sessionKey.keyId,
                privateAddress
            )

            val savedKeyData = readKeyData(sessionKeyFilePath)
            assertEquals(
                sessionKeypair.privateKey.encoded.asList(),
                savedKeyData.readBinaryData("private_key").data.asList()
            )
        }

        @Test
        override fun `Existing file should be updated if key already existed`() = runBlockingTest {
            val keystore = MockFilePrivateKeyStore(keystoreRoot)
            keystore.saveSessionKey(
                sessionKeypair.privateKey,
                sessionKeypair.sessionKey.keyId,
                privateAddress
            )

            // Replace the private key
            val differentSessionKeyPair = SessionKeyPair.generate()
            keystore.saveSessionKey(
                differentSessionKeyPair.privateKey,
                sessionKeypair.sessionKey.keyId,
                privateAddress
            )

            val savedKeyData = readKeyData(sessionKeyFilePath)
            assertEquals(
                differentSessionKeyPair.privateKey.encoded.asList(),
                savedKeyData.readBinaryData("private_key").data.asList()
            )
        }

        @Test
        fun `Peer private address should be stored if present`() = runBlockingTest {
            val keystore = MockFilePrivateKeyStore(keystoreRoot)

            keystore.saveSessionKey(
                sessionKeypair.privateKey,
                sessionKeypair.sessionKey.keyId,
                privateAddress,
                peerPrivateAddress,
            )

            val savedKeyData = readKeyData(sessionKeyFilePath)
            savedKeyData.readBinaryData("private_key")
            assertEquals(peerPrivateAddress, savedKeyData.readString("peer_private_address"))
        }

        @Test
        fun `Peer private address should not be stored if absent`() = runBlockingTest {
            val keystore = MockFilePrivateKeyStore(keystoreRoot)

            keystore.saveSessionKey(
                sessionKeypair.privateKey,
                sessionKeypair.sessionKey.keyId,
                privateAddress,
            )

            val savedKeyData = readKeyData(sessionKeyFilePath)
            savedKeyData.readBinaryData("private_key")
            assertEquals("", savedKeyData.readString("peer_private_address"))
        }
    }

    private fun byteArrayToHex(byteArray: ByteArray) =
        byteArray.joinToString("") { "%02x".format(it) }
}
