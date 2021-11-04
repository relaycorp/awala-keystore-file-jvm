package tech.relaycorp.awala.keystores.file

import java.io.File
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.createDirectory
import kotlin.io.path.createFile
import kotlin.io.path.deleteIfExists
import kotlin.io.path.exists
import kotlin.io.path.pathString
import kotlin.test.assertEquals
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Disabled
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class FileSessionPublicKeyStoreTest {
    private val tmpDirectory = Files.createTempDirectory("public-key-store-test-")
    private val rootDirectory = tmpDirectory.resolve("root")

    @BeforeEach
    fun createRootDirectory() {
        rootDirectory.createDirectory()
    }

    @AfterEach
    fun deleteRootDirectory() {
        if (rootDirectory.exists()) {
            rootDirectory.toFile().setReadable(true)

            Files.walk(rootDirectory)
                .sorted(Comparator.reverseOrder())
                .map(Path::toFile)
                .forEach(File::delete)
        }
    }

    @AfterAll
    fun deleteTmpDirectory() {
        tmpDirectory.deleteIfExists()
    }

    @Nested
    inner class Constructor {
        @Test
        fun `Root directory should be rejected if it isn't a directory`() {
            val rootDirectory = rootDirectory.resolve("file.txt")
            rootDirectory.createFile()

            val exception = assertThrows<FileKeystoreException> {
                FileSessionPublicKeyStore(rootDirectory)
            }

            assertEquals(
                "Root '${rootDirectory.pathString}' isn't a directory",
                exception.message
            )
        }

        @Test
        fun `Root directory should be refused if it isn't using an absolute path`() {
            val rootDirectory = File("relative").toPath()

            val exception = assertThrows<FileKeystoreException> {
                FileSessionPublicKeyStore(rootDirectory)
            }

            assertEquals(
                "Root directory must use an absolute path (got '${rootDirectory.pathString}')",
                exception.message
            )
        }

        @Test
        fun `Root directory should be rejected if it doesn't exist`() {
            val rootDirectory = tmpDirectory.resolve("non-existing")

            val exception = assertThrows<FileKeystoreException> {
                FileSessionPublicKeyStore(rootDirectory)
            }

            assertEquals(
                "Root '${rootDirectory.pathString}' doesn't exist",
                exception.message
            )
        }

        @Test
        fun `Root directory should be refused if it isn't readable`() {
            rootDirectory.toFile().setReadable(false)

            val exception = assertThrows<FileKeystoreException> {
                FileSessionPublicKeyStore(rootDirectory)
            }

            assertEquals(
                "Root '${rootDirectory.pathString}' isn't readable",
                exception.message
            )
        }

        @Test
        fun `Root directory should be refused if it isn't writable`() {
            rootDirectory.toFile().setWritable(false)

            val exception = assertThrows<FileKeystoreException> {
                FileSessionPublicKeyStore(rootDirectory)
            }

            assertEquals(
                "Root '${rootDirectory.pathString}' isn't writable",
                exception.message
            )
        }
    }

    @Nested
    inner class Save {
        @Test
        @Disabled
        fun `Parent directories should be created if they don't already exist`() {
        }

        @Test
        @Disabled
        fun `Errors creating parent directories should be wrapped`() {
        }

        @Test
        @Disabled
        fun `Key data should be stored in new file if there is no prior key for peer`() {
        }

        @Test
        @Disabled
        fun `Key data should be updated if there is a prior key for peer`() {
        }

        @Test
        @Disabled
        fun `Data should be flushed with fdatasync`() {
        }
    }
}
