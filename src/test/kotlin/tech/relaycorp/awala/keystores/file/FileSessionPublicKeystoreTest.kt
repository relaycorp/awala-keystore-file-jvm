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
import kotlinx.coroutines.test.runBlockingTest
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
    private val peerPrivateAddress = PDACertPath.PDA.subjectPrivateAddress

    private val sessionKeyPair = SessionKeyPair.generate()

    private val publicKeystoreRootPath = keystoreRoot.directory.resolve("public")
    private val keyDataFilePath = publicKeystoreRootPath.resolve(peerPrivateAddress)

    @Nested
    inner class Save {
        @Test
        fun `Parent directory should be reused if it already exists`() = runBlockingTest {
            @Suppress("BlockingMethodInNonBlockingContext")
            publicKeystoreRootPath.createDirectory()
            val keystore = FileSessionPublicKeystore(keystoreRoot)

            keystore.save(sessionKeyPair.sessionKey, peerPrivateAddress)

            readKeyData()
        }

        @Test
        fun `Parent directory should be created if it doesn't already exist`() = runBlockingTest {
            assertFalse(publicKeystoreRootPath.exists())
            val keystore = FileSessionPublicKeystore(keystoreRoot)

            keystore.save(sessionKeyPair.sessionKey, peerPrivateAddress)

            readKeyData()
        }

        @Test
        @DisabledOnOs(OS.WINDOWS)
        fun `Errors creating parent directory should be wrapped`() = runBlockingTest {
            keystoreRoot.directory.toFile().setExecutable(false)
            keystoreRoot.directory.toFile().setWritable(false)
            val keystore = FileSessionPublicKeystore(keystoreRoot)

            val exception = assertThrows<FileKeystoreException> {
                keystore.save(sessionKeyPair.sessionKey, peerPrivateAddress)
            }

            assertEquals(
                "Failed to create root directory for public keys",
                exception.message
            )
            assertTrue(exception.cause is IOException)
        }

        @Test
        fun `New file should be created if there is no prior key for peer`() = runBlockingTest {
            assertFalse(keyDataFilePath.exists())
            val creationTime = ZonedDateTime.now()
            val keystore = FileSessionPublicKeystore(keystoreRoot)

            keystore.save(sessionKeyPair.sessionKey, peerPrivateAddress, creationTime)

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
        fun `Existing file should be updated if there is a prior key for peer`() = runBlockingTest {
            val now = ZonedDateTime.now()
            val keystore = FileSessionPublicKeystore(keystoreRoot)
            keystore.save(sessionKeyPair.sessionKey, peerPrivateAddress, now.minusSeconds(1))
            val (newSessionKey) = SessionKeyPair.generate()

            keystore.save(newSessionKey, peerPrivateAddress, now)

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
        fun `Errors creating or updating file should be wrapped`() = runBlockingTest {
            val keystore = FileSessionPublicKeystore(keystoreRoot)
            // Make the read operation work but the subsequent write operation fail
            keystore.save(
                sessionKeyPair.sessionKey,
                peerPrivateAddress,
                ZonedDateTime.now().minusDays(1)
            )
            keyDataFilePath.toFile().setWritable(false)

            val exception = assertThrows<FileKeystoreException> {
                keystore.save(sessionKeyPair.sessionKey, peerPrivateAddress)
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
            runBlockingTest {
                publicKeystoreRootPath.deleteExisting()
                val keystore = FileSessionPublicKeystore(keystoreRoot)

                assertThrows<MissingKeyException> { keystore.retrieve(peerPrivateAddress) }
            }

        @Test
        fun `Key should be reported as missing if the file doesn't exist`() = runBlockingTest {
            val keystore = FileSessionPublicKeystore(keystoreRoot)

            assertThrows<MissingKeyException> { keystore.retrieve(peerPrivateAddress) }
        }

        @Test
        @DisabledOnOs(OS.WINDOWS) // Windows can't tell apart between not-readable and non-existing
        fun `Exception should be thrown if file isn't readable`() = runBlockingTest {
            keyDataFilePath.toFile().createNewFile()
            keyDataFilePath.toFile().setReadable(false)
            val keystore = FileSessionPublicKeystore(keystoreRoot)

            val exception = assertThrows<FileKeystoreException> {
                keystore.retrieve(peerPrivateAddress)
            }

            assertEquals("Failed to read key file", exception.message)
            assertTrue(exception.cause is IOException)
        }

        @Test
        fun `Exception should be thrown if file is not BSON-serialized`() = runBlockingTest {
            saveKeyData("not BSON".toByteArray())
            val keystore = FileSessionPublicKeystore(keystoreRoot)

            val exception = assertThrows<FileKeystoreException> {
                keystore.retrieve(peerPrivateAddress)
            }

            assertEquals("Key file is malformed", exception.message)
            assertTrue(exception.cause is BSONException)
        }

        @Test
        fun `Exception should be thrown if key id is missing`() = runBlockingTest {
            saveKeyData {
                writeBinaryData("key_der", BsonBinary(sessionKeyPair.sessionKey.publicKey.encoded))
                writeInt32("creation_timestamp", creationTimestamp)
            }
            val keystore = FileSessionPublicKeystore(keystoreRoot)

            val exception = assertThrows<FileKeystoreException> {
                keystore.retrieve(peerPrivateAddress)
            }

            assertEquals("Key file is malformed", exception.message)
            assertTrue(exception.cause is BSONException)
        }

        @Test
        fun `Exception should be thrown if public key is missing`() = runBlockingTest {
            saveKeyData {
                writeBinaryData("key_id", BsonBinary(sessionKeyPair.sessionKey.keyId))
                writeInt32("creation_timestamp", creationTimestamp)
            }
            val keystore = FileSessionPublicKeystore(keystoreRoot)

            val exception = assertThrows<FileKeystoreException> {
                keystore.retrieve(peerPrivateAddress)
            }

            assertEquals("Key file is malformed", exception.message)
            assertTrue(exception.cause is BSONException)
        }

        @Test
        fun `Exception should be thrown if creation timestamp is missing`() = runBlockingTest {
            saveKeyData {
                writeBinaryData("key_id", BsonBinary(sessionKeyPair.sessionKey.keyId))
                writeBinaryData("key_der", BsonBinary(sessionKeyPair.sessionKey.publicKey.encoded))
            }
            val keystore = FileSessionPublicKeystore(keystoreRoot)

            val exception = assertThrows<FileKeystoreException> {
                keystore.retrieve(peerPrivateAddress)
            }

            assertEquals("Key file is malformed", exception.message)
            assertTrue(exception.cause is BsonInvalidOperationException)
        }

        @Test
        fun `Data should be returned if file exists and is valid`() = runBlockingTest {
            val keystore = FileSessionPublicKeystore(keystoreRoot)
            keystore.save(sessionKeyPair.sessionKey, peerPrivateAddress)

            val key = keystore.retrieve(peerPrivateAddress)

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
        fun `Deletion should be skipped if the root directory doesn't exist`() = runBlockingTest {
            publicKeystoreRootPath.deleteExisting()
            val keystore = FileSessionPublicKeystore(keystoreRoot)

            keystore.delete(peerPrivateAddress)
        }

        @Test
        fun `Deletion should be skipped if the file doesn't exist`() = runBlockingTest {
            val keystore = FileSessionPublicKeystore(keystoreRoot)

            keystore.delete(peerPrivateAddress)
        }

        @Test
        fun `File should be deleted if it exists`() = runBlockingTest {
            val keystore = FileSessionPublicKeystore(keystoreRoot)
            keystore.save(sessionKeyPair.sessionKey, peerPrivateAddress)

            keystore.delete(peerPrivateAddress)

            assertThrows<MissingKeyException> { keystore.retrieve(peerPrivateAddress) }
        }
    }
}
