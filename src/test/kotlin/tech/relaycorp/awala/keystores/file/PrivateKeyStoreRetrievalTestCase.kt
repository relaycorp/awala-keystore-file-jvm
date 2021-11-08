package tech.relaycorp.awala.keystores.file

import java.io.IOException
import java.nio.file.Path
import kotlin.io.path.createDirectories
import kotlin.io.path.createFile
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
import tech.relaycorp.relaynet.keystores.MissingKeyException

@ExperimentalCoroutinesApi
@Suppress("BlockingMethodInNonBlockingContext")
abstract class PrivateKeyStoreRetrievalTestCase(
    private val keystoreRoot: FileKeystoreRoot,
    private val keyFilePath: Path,
    private val retrieveMethod: suspend FilePrivateKeyStore.() -> Unit
) {
    @Test
    fun `Key should be reported as missing if parent directory doesn't exist`() = runBlockingTest {
        assertFalse(keyFilePath.parent.exists())
        val keystore = MockFilePrivateKeyStore(keystoreRoot)

        assertThrows<MissingKeyException> { retrieveMethod(keystore) }
    }

    @Test
    fun `Key should be reported as missing if the file doesn't exist`() = runBlockingTest {
        keyFilePath.parent.createDirectories()
        val keystore = MockFilePrivateKeyStore(keystoreRoot)

        assertThrows<MissingKeyException> { retrieveMethod(keystore) }
    }

    @Test
    @DisabledOnOs(OS.WINDOWS) // Windows can't tell apart between not-readable and non-existing
    fun `Exception should be thrown if file isn't readable`() = runBlockingTest {
        keyFilePath.parent.createDirectories()
        keyFilePath.createFile()
        keyFilePath.toFile().setReadable(false)
        val keystore = MockFilePrivateKeyStore(keystoreRoot)

        val exception = assertThrows<FileKeystoreException> { retrieveMethod(keystore) }

        assertEquals("Failed to read key file", exception.message)
        assertTrue(exception.cause is IOException)
    }

    abstract fun `Private key should be returned if file exists`()
}
