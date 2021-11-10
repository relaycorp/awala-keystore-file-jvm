package tech.relaycorp.awala.keystores.file

import java.nio.file.Files
import kotlin.io.path.createDirectory
import kotlin.io.path.exists
import kotlin.test.assertTrue
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach

abstract class KeystoreTestCase {
    private val rootDirectoryPath = Files.createTempDirectory("public-key-store-test-")
    protected val keystoreRoot = FileKeystoreRoot(rootDirectoryPath.toFile())

    @BeforeEach
    fun createRootDirectory() {
        if (!rootDirectoryPath.exists()) {
            rootDirectoryPath.createDirectory()
        }
    }

    @AfterEach
    fun deleteRootDirectory() {
        // Make contents writable first or else the deletion will fail
        Files.walk(rootDirectoryPath).forEach { it.toFile().setWritable(true) }
        assertTrue(
            rootDirectoryPath.toFile().deleteRecursively(),
            "Root directory should've been deleted",
        )
    }
}
