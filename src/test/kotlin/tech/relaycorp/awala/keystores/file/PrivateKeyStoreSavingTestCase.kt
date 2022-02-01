package tech.relaycorp.awala.keystores.file

import java.io.IOException
import java.nio.file.Path
import kotlin.io.path.createDirectories
import kotlin.io.path.exists
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runBlockingTest
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.condition.DisabledOnOs
import org.junit.jupiter.api.condition.OS

@ExperimentalCoroutinesApi
@Suppress("BlockingMethodInNonBlockingContext")
abstract class PrivateKeyStoreSavingTestCase(
    private val keystoreRoot: FileKeystoreRoot,
    private val keyFilePath: Path,
    private val saveMethod: suspend FilePrivateKeyStore.() -> Unit
) {
    @Test
    fun `Parent subdirectory should be reused if it exists`() = runBlockingTest {
        keyFilePath.parent.createDirectories()
        val keystore = MockFilePrivateKeyStore(keystoreRoot)

        saveMethod(keystore)

        assertTrue(keyFilePath.exists())
    }

    @Test
    fun `Parent directory should be created if it doesn't exist`() = runBlockingTest {
        assertFalse(keyFilePath.parent.exists())
        val keystore = MockFilePrivateKeyStore(keystoreRoot)

        saveMethod(keystore)

        assertTrue(keyFilePath.exists())
    }

    @Test
    fun `Root directory should be created if it doesn't exist`() = runBlockingTest {
        keystoreRoot.directory.delete()
        val keystore = MockFilePrivateKeyStore(keystoreRoot)

        saveMethod(keystore)

        assertTrue(keyFilePath.exists())
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    fun `Errors creating node subdirectory should be wrapped`() = runBlockingTest {
        keystoreRoot.directory.setExecutable(false)
        keystoreRoot.directory.setWritable(false)
        val keystore = MockFilePrivateKeyStore(keystoreRoot)

        val exception = assertThrows<FileKeystoreException> {
            saveMethod(keystore)
        }

        assertEquals(
            "Failed to create root directory for private keys",
            exception.message
        )
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    fun `Errors creating or updating file should be wrapped`() = runBlockingTest {
        keyFilePath.parent.createDirectories()
        keyFilePath.toFile().createNewFile()
        keyFilePath.toFile().setWritable(false)
        val keystore = MockFilePrivateKeyStore(keystoreRoot)

        val exception = assertThrows<FileKeystoreException> {
            saveMethod(keystore)
        }

        assertEquals("Failed to save key file", exception.message)
        assertTrue(exception.cause is IOException)
    }

    @Test
    fun `New file should be created if key is new`() = runBlockingTest {
        assertFalse(keyFilePath.exists())
        val keystore = MockFilePrivateKeyStore(keystoreRoot)

        saveMethod(keystore)

        assertTrue(keyFilePath.exists())
    }

    @Test
    abstract fun `Private key should be stored`()
}
