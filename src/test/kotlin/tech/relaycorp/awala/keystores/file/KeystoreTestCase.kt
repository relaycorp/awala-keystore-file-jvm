package tech.relaycorp.awala.keystores.file

import java.io.File
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.createDirectory
import kotlin.io.path.exists
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
        Files.walk(rootDirectoryPath)
            .sorted(Comparator.reverseOrder())
            .map(Path::toFile)
            .forEach(File::delete)
    }
}
