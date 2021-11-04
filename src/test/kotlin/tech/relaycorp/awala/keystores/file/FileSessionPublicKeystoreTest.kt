package tech.relaycorp.awala.keystores.file

import java.io.IOException
import java.nio.ByteBuffer
import java.nio.file.Path
import java.time.ZonedDateTime
import kotlin.io.path.createDirectories
import kotlin.io.path.createDirectory
import kotlin.io.path.exists
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runBlockingTest
import org.bson.BsonBinaryReader
import org.junit.jupiter.api.Disabled
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import tech.relaycorp.relaynet.SessionKeyPair
import tech.relaycorp.relaynet.testing.pki.PDACertPath

@ExperimentalCoroutinesApi
class FileSessionPublicKeystoreTest : KeystoreTestCase() {
    private val peerPrivateAddress = PDACertPath.PRIVATE_ENDPOINT.subjectPrivateAddress

    private val sessionKeyPair = SessionKeyPair.generate()

    @Nested
    inner class Save {
        private val publicKeystoreRootPath = keystoreRoot.directory.resolve("public")

        private val keyDataFilePath = publicKeystoreRootPath.resolve(peerPrivateAddress)

        @Test
        fun `Parent directory should be reused if it already exists`() = runBlockingTest {
            @Suppress("BlockingMethodInNonBlockingContext")
            publicKeystoreRootPath.createDirectory()
            val keystore = FileSessionPublicKeystore(keystoreRoot)

            keystore.save(sessionKeyPair.sessionKey, peerPrivateAddress)

            readKeyData(keyDataFilePath)
        }

        @Test
        fun `Parent directory should be created if it doesn't already exist`() = runBlockingTest {
            assertFalse(publicKeystoreRootPath.exists())
            val keystore = FileSessionPublicKeystore(keystoreRoot)

            keystore.save(sessionKeyPair.sessionKey, peerPrivateAddress)

            readKeyData(keyDataFilePath)
        }

        @Test
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

            val savedKeyData = readKeyData(keyDataFilePath)
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

            val savedKeyData = readKeyData(keyDataFilePath)
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
            @Suppress("BlockingMethodInNonBlockingContext")
            keyDataFilePath.createDirectories() // Make the path a directory instead of a file
            val keystore = FileSessionPublicKeystore(keystoreRoot)

            val exception = assertThrows<FileKeystoreException> {
                keystore.save(sessionKeyPair.sessionKey, peerPrivateAddress)
            }

            assertEquals(
                "Failed to save key data to file",
                exception.message
            )
            assertTrue(exception.cause is IOException)
        }

        private fun readKeyData(dataFilePath: Path) =
            BsonBinaryReader(ByteBuffer.wrap(dataFilePath.toFile().readBytes())).also {
                it.readStartDocument()
            }
    }

    @Nested
    inner class Retrieve {
        @Test
        @Disabled
        fun `Null should be returned if file doesn't exist`() {
        }

        @Test
        @Disabled
        fun `Data should be returned if file exists and is valid`() {
        }

        @Test
        @Disabled
        fun `Exception should be thrown if file isn't readable`() {
        }

        @Test
        @Disabled
        fun `Exception should be thrown if file is not BSON-serialized`() {
        }

        @Test
        @Disabled
        fun `Exception should be thrown if key id is missing`() {
        }

        @Test
        @Disabled
        fun `Exception should be thrown if key serialization is missing`() {
        }

        @Test
        @Disabled
        fun `Exception should be thrown if creation timestamp is missing`() {
        }
    }
}
