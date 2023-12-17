package tech.relaycorp.awala.keystores.file

import java.io.IOException
import java.nio.ByteBuffer
import java.time.ZonedDateTime
import kotlin.io.path.createDirectory
import kotlin.io.path.deleteExisting
import kotlin.io.path.exists
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import org.bson.BSONException
import org.bson.BsonBinary
import org.bson.BsonBinaryReader
import org.bson.BsonBinaryWriter
import org.bson.BsonInvalidOperationException
import org.bson.io.BasicOutputBuffer
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.condition.DisabledOnOs
import org.junit.jupiter.api.condition.OS
import tech.relaycorp.relaynet.SessionKeyPair
import tech.relaycorp.relaynet.keystores.MissingKeyException
import tech.relaycorp.relaynet.testing.pki.PDACertPath

@ExperimentalCoroutinesApi
@Suppress("BlockingMethodInNonBlockingContext")
class FileSessionPublicKeystoreTest : KeystoreTestCase() {
    private val nodeId = PDACertPath.PDA.issuerCommonName
    private val peerId = PDACertPath.PDA.subjectId

    private val sessionKeyPair = SessionKeyPair.generate()

    private val publicKeystoreRootPath = keystoreRoot.directory.resolve("public").toPath()
    private val keyDataFilePath = publicKeystoreRootPath.resolve("$nodeId-$peerId")

    @Nested
    inner class Save {
        @Test
        fun `Keystore directory should be reused if it already exists`() = runTest {
            publicKeystoreRootPath.createDirectory()
            val keystore = FileSessionPublicKeystore(keystoreRoot)

            keystore.save(sessionKeyPair.sessionKey, nodeId, peerId)

            readKeyData()
        }

        @Test
        fun `Keystore directory should be created if it doesn't already exist`() = runTest {
            assertFalse(publicKeystoreRootPath.exists())
            val keystore = FileSessionPublicKeystore(keystoreRoot)

            keystore.save(sessionKeyPair.sessionKey, nodeId, peerId)

            readKeyData()
        }

        @Test
        fun `Root directory should be created if it doesn't already exist`() = runTest {
            keystoreRoot.directory.delete()
            val keystore = FileSessionPublicKeystore(keystoreRoot)

            keystore.save(sessionKeyPair.sessionKey, nodeId, peerId)

            readKeyData()
        }

        @Test
        @DisabledOnOs(OS.WINDOWS)
        fun `Errors creating parent directory should be wrapped`() = runTest {
            keystoreRoot.directory.setExecutable(false)
            keystoreRoot.directory.setWritable(false)
            val keystore = FileSessionPublicKeystore(keystoreRoot)

            val exception = assertThrows<FileKeystoreException> {
                keystore.save(sessionKeyPair.sessionKey, nodeId, peerId)
            }

            assertEquals(
                "Failed to create root directory for public keys",
                exception.message
            )
        }

        @Test
        fun `New file should be created if there is no prior key for peer`() = runTest {
            assertFalse(keyDataFilePath.exists())
            val creationTime = ZonedDateTime.now()
            val keystore = FileSessionPublicKeystore(keystoreRoot)

            keystore.save(sessionKeyPair.sessionKey, nodeId, peerId, creationTime)

            val savedKeyData = readKeyData()
            assertEquals(
                sessionKeyPair.sessionKey.keyId.asList(),
                savedKeyData.readBinaryData("key_id").data.asList()
            )
            assertEquals(
                sessionKeyPair.sessionKey.publicKey.encoded.asList(),
                savedKeyData.readBinaryData("key_der").data.asList()
            )
            assertEquals(
                creationTime.toEpochSecond(),
                savedKeyData.readInt32("creation_timestamp").toLong()
            )
        }

        @Test
        fun `Existing file should be updated if there is a prior key for peer`() = runTest {
            val now = ZonedDateTime.now()
            val keystore = FileSessionPublicKeystore(keystoreRoot)
            keystore.save(sessionKeyPair.sessionKey, nodeId, peerId, now.minusSeconds(1))
            val (newSessionKey) = SessionKeyPair.generate()

            keystore.save(newSessionKey, nodeId, peerId, now)

            val savedKeyData = readKeyData()
            assertEquals(
                newSessionKey.keyId.asList(),
                savedKeyData.readBinaryData("key_id").data.asList()
            )
            assertEquals(
                newSessionKey.publicKey.encoded.asList(),
                savedKeyData.readBinaryData("key_der").data.asList()
            )
            assertEquals(
                now.toEpochSecond(),
                savedKeyData.readInt32("creation_timestamp").toLong()
            )
        }

        @Test
        fun `Errors creating or updating file should be wrapped`() = runTest {
            val keystore = FileSessionPublicKeystore(keystoreRoot)
            // Make the read operation work but the subsequent write operation fail
            keystore.save(
                sessionKeyPair.sessionKey,
                nodeId,
                peerId,
                ZonedDateTime.now().minusDays(1)
            )
            keyDataFilePath.toFile().setWritable(false)

            val exception = assertThrows<FileKeystoreException> {
                keystore.save(sessionKeyPair.sessionKey, nodeId, peerId)
            }

            assertEquals(
                "Failed to save key data to file",
                exception.message
            )
            assertTrue(exception.cause is IOException)
        }

        private fun readKeyData() =
            BsonBinaryReader(ByteBuffer.wrap(keyDataFilePath.toFile().readBytes())).also {
                it.readStartDocument()
            }
    }

    @Nested
    inner class Retrieve {
        private val creationTimestamp = ZonedDateTime.now().toEpochSecond().toInt()

        @BeforeEach
        fun createRootDirectory() {
            publicKeystoreRootPath.createDirectory()
        }

        @Test
        fun `Key should be reported as missing if root directory doesn't exist`() =
            runTest {
                publicKeystoreRootPath.deleteExisting()
                val keystore = FileSessionPublicKeystore(keystoreRoot)

                assertThrows<MissingKeyException> { keystore.retrieve(nodeId, peerId) }
            }

        @Test
        fun `Key should be reported as missing if the file doesn't exist`() = runTest {
            val keystore = FileSessionPublicKeystore(keystoreRoot)

            assertThrows<MissingKeyException> { keystore.retrieve(nodeId, peerId) }
        }

        @Test
        @DisabledOnOs(OS.WINDOWS) // Windows can't tell apart between not-readable and non-existing
        fun `Exception should be thrown if file isn't readable`() = runTest {
            keyDataFilePath.toFile().createNewFile()
            keyDataFilePath.toFile().setReadable(false)
            val keystore = FileSessionPublicKeystore(keystoreRoot)

            val exception = assertThrows<FileKeystoreException> {
                keystore.retrieve(nodeId, peerId)
            }

            assertEquals("Failed to read key file", exception.message)
            assertTrue(exception.cause is IOException)
        }

        @Test
        fun `Exception should be thrown if file is not BSON-serialized`() = runTest {
            saveKeyData("not BSON".toByteArray())
            val keystore = FileSessionPublicKeystore(keystoreRoot)

            val exception = assertThrows<FileKeystoreException> {
                keystore.retrieve(nodeId, peerId)
            }

            assertEquals("Key file is malformed", exception.message)
            assertTrue(exception.cause is BSONException)
        }

        @Test
        fun `Exception should be thrown if key id is missing`() = runTest {
            saveKeyData {
                writeBinaryData("key_der", BsonBinary(sessionKeyPair.sessionKey.publicKey.encoded))
                writeInt32("creation_timestamp", creationTimestamp)
            }
            val keystore = FileSessionPublicKeystore(keystoreRoot)

            val exception = assertThrows<FileKeystoreException> {
                keystore.retrieve(nodeId, peerId)
            }

            assertEquals("Key file is malformed", exception.message)
            assertTrue(exception.cause is BSONException)
        }

        @Test
        fun `Exception should be thrown if public key is missing`() = runTest {
            saveKeyData {
                writeBinaryData("key_id", BsonBinary(sessionKeyPair.sessionKey.keyId))
                writeInt32("creation_timestamp", creationTimestamp)
            }
            val keystore = FileSessionPublicKeystore(keystoreRoot)

            val exception = assertThrows<FileKeystoreException> {
                keystore.retrieve(nodeId, peerId)
            }

            assertEquals("Key file is malformed", exception.message)
            assertTrue(exception.cause is BSONException)
        }

        @Test
        fun `Exception should be thrown if creation timestamp is missing`() = runTest {
            saveKeyData {
                writeBinaryData("key_id", BsonBinary(sessionKeyPair.sessionKey.keyId))
                writeBinaryData("key_der", BsonBinary(sessionKeyPair.sessionKey.publicKey.encoded))
            }
            val keystore = FileSessionPublicKeystore(keystoreRoot)

            val exception = assertThrows<FileKeystoreException> {
                keystore.retrieve(nodeId, peerId)
            }

            assertEquals("Key file is malformed", exception.message)
            assertTrue(exception.cause is BsonInvalidOperationException)
        }

        @Test
        fun `Data should be returned if file exists and is valid`() = runTest {
            val keystore = FileSessionPublicKeystore(keystoreRoot)
            keystore.save(sessionKeyPair.sessionKey, nodeId, peerId)

            val key = keystore.retrieve(nodeId, peerId)

            assertEquals(sessionKeyPair.sessionKey, key)
        }

        private fun saveKeyData(data: ByteArray) = keyDataFilePath.toFile().writeBytes(data)

        private fun saveKeyData(writeBsonFields: BsonBinaryWriter.() -> Unit) {
            val bsonSerialization = BasicOutputBuffer().use { buffer ->
                BsonBinaryWriter(buffer).use {
                    it.writeStartDocument()
                    writeBsonFields(it)
                    it.writeEndDocument()
                }
                buffer.toByteArray()
            }
            saveKeyData(bsonSerialization)
        }
    }

    @Nested
    inner class Delete {
        @BeforeEach
        fun createRootDirectory() {
            publicKeystoreRootPath.createDirectory()
        }

        @Test
        fun `Deletion should be skipped if the root directory doesn't exist`() = runTest {
            publicKeystoreRootPath.deleteExisting()
            val keystore = FileSessionPublicKeystore(keystoreRoot)

            keystore.delete(nodeId, peerId)
        }

        @Test
        fun `Deletion should be skipped if the file doesn't exist`() = runTest {
            val keystore = FileSessionPublicKeystore(keystoreRoot)

            keystore.delete(nodeId, peerId)
        }

        @Test
        fun `File should be deleted if it exists`() = runTest {
            val keystore = FileSessionPublicKeystore(keystoreRoot)
            keystore.save(sessionKeyPair.sessionKey, nodeId, peerId)

            keystore.delete(nodeId, peerId)

            assertThrows<MissingKeyException> { keystore.retrieve(nodeId, peerId) }
        }
    }
}
