package tech.relaycorp.awala.keystores.file

import java.nio.file.Path
import kotlin.io.path.exists
import kotlin.io.path.isDirectory
import kotlin.io.path.isReadable
import kotlin.io.path.isWritable
import kotlin.io.path.pathString

public class FileKeystoreRoot @Throws(FileKeystoreException::class) constructor(
    internal val directory: Path
) {
    init {
        if (!directory.isAbsolute) {
            throw FileKeystoreException(
                "Root directory must use an absolute path (got '${directory.pathString}')"
            )
        }
        if (!directory.exists()) {
            throw FileKeystoreException(
                "Root '${directory.pathString}' doesn't exist"
            )
        }
        if (!directory.isDirectory()) {
            throw FileKeystoreException("Root '${directory.pathString}' isn't a directory")
        }
        // Check permissions (read and write operations are always allowed on Windows)
        if (!directory.isReadable()) {
            throw FileKeystoreException("Root '${directory.pathString}' isn't readable")
        }
        if (!directory.isWritable()) {
            throw FileKeystoreException("Root '${directory.pathString}' isn't writable")
        }
    }
}
