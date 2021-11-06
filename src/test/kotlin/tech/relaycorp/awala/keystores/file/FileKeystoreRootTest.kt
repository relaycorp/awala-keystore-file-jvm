package tech.relaycorp.awala.keystores.file

import java.io.File
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.createDirectory
import kotlin.io.path.deleteIfExists
import kotlin.io.path.exists
import kotlin.io.path.pathString
import kotlin.test.assertEquals
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.condition.DisabledOnOs
import org.junit.jupiter.api.condition.OS

class FileKeystoreRootTest {
    private val tmpDirectoryPath = Files.createTempDirectory("public-key-store-test-")
    private val rootDirectoryPath = tmpDirectoryPath.resolve("root")
    private val rootDirectoryFile = rootDirectoryPath.toFile()

    @BeforeEach
    fun createRootDirectory() {
        rootDirectoryPath.createDirectory()
    }

    @AfterEach
    fun deleteRootDirectory() {
        if (rootDirectoryPath.exists()) {
            rootDirectoryPath.toFile().setReadable(true)

            Files.walk(rootDirectoryPath)
                .sorted(Comparator.reverseOrder())
                .map(Path::toFile)
                .forEach(File::delete)
        }
    }

    @AfterAll
    fun deleteTmpDirectory() {
        tmpDirectoryPath.deleteIfExists()
    }

    @Nested
    inner class Constructor {
        @Test
        fun `Root directory should be rejected if it isn't a directory`() {
            val file = rootDirectoryFile.resolve("file.txt")
            file.createNewFile()

            val exception = assertThrows<FileKeystoreException> {
                FileKeystoreRoot(file)
            }

            assertEquals(
                "Root '${file.path}' isn't a directory",
                exception.message
            )
        }

        @Test
        fun `Root directory should be refused if it isn't using an absolute path`() {
            val rootDirectory = File("relative")

            val exception = assertThrows<FileKeystoreException> {
                FileKeystoreRoot(rootDirectory)
            }

            assertEquals(
                "Root directory must use an absolute path (got '${rootDirectory.path}')",
                exception.message
            )
        }

        @Test
        fun `Root directory should be rejected if it doesn't exist`() {
            val rootDirectory = tmpDirectoryPath.resolve("non-existing").toFile()

            val exception = assertThrows<FileKeystoreException> {
                FileKeystoreRoot(rootDirectory)
            }

            assertEquals(
                "Root '${rootDirectory.path}' doesn't exist",
                exception.message
            )
        }

        @Test
        @DisabledOnOs(OS.WINDOWS)
        fun `Root directory should be refused if it isn't readable`() {
            rootDirectoryPath.toFile().setReadable(false)

            val exception = assertThrows<FileKeystoreException> {
                FileKeystoreRoot(rootDirectoryFile)
            }

            assertEquals(
                "Root '${rootDirectoryPath.pathString}' isn't readable",
                exception.message
            )
        }

        @Test
        @DisabledOnOs(OS.WINDOWS)
        fun `Root directory should be refused if it isn't writable`() {
            rootDirectoryPath.toFile().setWritable(false)

            val exception = assertThrows<FileKeystoreException> {
                FileKeystoreRoot(rootDirectoryFile)
            }

            assertEquals(
                "Root '${rootDirectoryPath.pathString}' isn't writable",
                exception.message
            )
        }
    }
}
