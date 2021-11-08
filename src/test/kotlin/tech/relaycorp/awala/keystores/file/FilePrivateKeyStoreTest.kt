package tech.relaycorp.awala.keystores.file

import java.nio.ByteBuffer
import java.nio.file.Path
import java.time.ZonedDateTime
import kotlin.io.path.createDirectories
import kotlin.io.path.exists
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runBlockingTest
import org.bson.BSONException
import org.bson.BsonBinaryReader
import org.bson.BsonBinaryWriter
import org.bson.io.BasicOutputBuffer
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import tech.relaycorp.relaynet.SessionKeyPair
import tech.relaycorp.relaynet.issueEndpointCertificate
import tech.relaycorp.relaynet.keystores.IdentityKeyPair
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
    private val boundSessionKeyFilePath =
        nodeDirectoryPath.resolve("session").resolve(peerPrivateAddress).resolve(
            byteArrayToHex(sessionKeypair.sessionKey.keyId)
        )
    private val unboundSessionKeyFilePath = nodeDirectoryPath.resolve("session").resolve(
        byteArrayToHex(sessionKeypair.sessionKey.keyId)
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

        private fun readKeyData(path: Path) = BsonBinaryReader(
            ByteBuffer.wrap(MockFilePrivateKeyStore.readFile(path.toFile()))
        ).also {
            it.readStartDocument()
        }
    }

    @Nested
    inner class RetrieveIdentity : PrivateKeyStoreRetrievalTestCase(
        keystoreRoot,
        identityKeyFilePath,
        { retrieveIdentityKey(privateAddress) }
    ) {

        @Test
        fun `Exception should be thrown if file is not BSON-serialized`() = runBlockingTest {
            identityKeyFilePath.parent.createDirectories()
            identityKeyFilePath.toFile().writeBytes("Not BSON".toByteArray())
            val keystore = MockFilePrivateKeyStore(keystoreRoot)

            val exception =
                assertThrows<FileKeystoreException> { keystore.retrieveIdentityKey(privateAddress) }

            assertEquals("Key file is malformed", exception.message)
            assertTrue(exception.cause is BSONException)
        }

        @Test
        fun `Exception should be thrown if private key is missing`() = runBlockingTest {
            saveKeyData(identityKeyFilePath) { }
            val keystore = MockFilePrivateKeyStore(keystoreRoot)

            val exception =
                assertThrows<FileKeystoreException> { keystore.retrieveIdentityKey(privateAddress) }

            assertEquals("Key file is malformed", exception.message)
            assertTrue(exception.cause is BSONException)
        }

        @Test
        override fun `Private key should be returned if file exists`() = runBlockingTest {
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

        private fun saveKeyData(path: Path, writeBsonFields: BsonBinaryWriter.() -> Unit) {
            if (!path.parent.exists()) {
                path.parent.createDirectories()
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
    inner class AllIdentityKeys {
        @Test
        fun `Nothing should be returned if store is empty`() = runBlockingTest {
            val keystore = MockFilePrivateKeyStore(keystoreRoot)

            val allIdentityKeys = keystore.retrieveAllIdentityKeys()

            assertEquals(0, allIdentityKeys.size)
        }

        @Test
        fun `All identity key pairs should be returned`() = runBlockingTest {
            val keystore = MockFilePrivateKeyStore(keystoreRoot)
            keystore.saveIdentityKey(privateKey, certificate)
            val extraPrivateKey = KeyPairSet.PDA_GRANTEE.private
            val extraCertificate = PDACertPath.PDA
            keystore.saveIdentityKey(extraPrivateKey, extraCertificate)

            val allIdentityKeys = keystore.retrieveAllIdentityKeys()

            assertEquals(2, allIdentityKeys.size)
            assertContains(allIdentityKeys, IdentityKeyPair(privateKey, certificate))
            assertContains(allIdentityKeys, IdentityKeyPair(extraPrivateKey, extraCertificate))
        }

        @Test
        fun `Irrelevant subdirectories should be ignored`() = runBlockingTest {
            val keystore = MockFilePrivateKeyStore(keystoreRoot)
            keystore.saveIdentityKey(privateKey, certificate)
            privateKeystoreRootFile.resolve("invalid").toPath().createDirectories()

            val allIdentityKeys = keystore.retrieveAllIdentityKeys()

            assertEquals(1, allIdentityKeys.size)
            assertContains(allIdentityKeys, IdentityKeyPair(privateKey, certificate))
        }

        @Test
        fun `Irrelevant files should be ignored`() = runBlockingTest {
            val keystore = MockFilePrivateKeyStore(keystoreRoot)
            keystore.saveIdentityKey(privateKey, certificate)
            privateKeystoreRootFile.resolve("invalid").createNewFile()

            val allIdentityKeys = keystore.retrieveAllIdentityKeys()

            assertEquals(1, allIdentityKeys.size)
            assertContains(allIdentityKeys, IdentityKeyPair(privateKey, certificate))
        }
    }

    @Nested
    inner class SaveSession : PrivateKeyStoreSavingTestCase(
        keystoreRoot,
        unboundSessionKeyFilePath,
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

            assertEquals(
                sessionKeypair.privateKey.encoded.asList(),
                readKeyData(unboundSessionKeyFilePath).asList()
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

            assertEquals(
                differentSessionKeyPair.privateKey.encoded.asList(),
                readKeyData(unboundSessionKeyFilePath).asList()
            )
        }

        @Test
        fun `File should be stored under peer subdirectory if key is bound`() = runBlockingTest {
            val keystore = MockFilePrivateKeyStore(keystoreRoot)

            keystore.saveSessionKey(
                sessionKeypair.privateKey,
                sessionKeypair.sessionKey.keyId,
                privateAddress,
                peerPrivateAddress,
            )

            assertEquals(
                sessionKeypair.privateKey.encoded.asList(),
                readKeyData(boundSessionKeyFilePath).asList()
            )
        }

        @Test
        fun `File should not be stored under a peer subdirectory if key is unbound`() =
            runBlockingTest {
                val keystore = MockFilePrivateKeyStore(keystoreRoot)

                keystore.saveSessionKey(
                    sessionKeypair.privateKey,
                    sessionKeypair.sessionKey.keyId,
                    privateAddress,
                )

                assertEquals(
                    sessionKeypair.privateKey.encoded.asList(),
                    readKeyData(unboundSessionKeyFilePath).asList()
                )
            }

        private fun readKeyData(path: Path) = MockFilePrivateKeyStore.readFile(path.toFile())
    }

    @Nested
    inner class RetrieveSession : PrivateKeyStoreRetrievalTestCase(
        keystoreRoot,
        unboundSessionKeyFilePath,
        {
            retrieveSessionKey(
                sessionKeypair.sessionKey.keyId,
                privateAddress,
                peerPrivateAddress
            )
        }
    ) {
        override fun `Private key should be returned if file exists`() = runBlockingTest {
            val keystore = MockFilePrivateKeyStore(keystoreRoot)
            keystore.saveSessionKey(
                sessionKeypair.privateKey,
                sessionKeypair.sessionKey.keyId,
                privateAddress
            )

            val sessionPrivateKey = keystore.retrieveSessionKey(
                sessionKeypair.sessionKey.keyId,
                privateAddress,
                peerPrivateAddress
            )

            assertEquals(sessionKeypair.privateKey, sessionPrivateKey)
        }

        @Test
        fun `Bound keys should be retrieved`() = runBlockingTest {
            val keystore = MockFilePrivateKeyStore(keystoreRoot)
            keystore.saveSessionKey(
                sessionKeypair.privateKey,
                sessionKeypair.sessionKey.keyId,
                privateAddress,
                peerPrivateAddress
            )

            val privateKey = keystore.retrieveSessionKey(
                sessionKeypair.sessionKey.keyId,
                privateAddress,
                peerPrivateAddress
            )

            assertEquals(sessionKeypair.privateKey.encoded.asList(), privateKey.encoded.asList())
        }

        @Test
        fun `Unbound keys should be retrieved`() = runBlockingTest {
            val keystore = MockFilePrivateKeyStore(keystoreRoot)
            keystore.saveSessionKey(
                sessionKeypair.privateKey,
                sessionKeypair.sessionKey.keyId,
                privateAddress,
            )

            val privateKey = keystore.retrieveSessionKey(
                sessionKeypair.sessionKey.keyId,
                privateAddress,
                peerPrivateAddress
            )

            assertEquals(sessionKeypair.privateKey.encoded.asList(), privateKey.encoded.asList())
        }
    }

    private fun byteArrayToHex(byteArray: ByteArray) =
        byteArray.joinToString("") { "%02x".format(it) }
}
