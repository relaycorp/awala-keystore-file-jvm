package tech.relaycorp.awala.keystores.file

import java.io.File

public class FileKeystoreRoot @Throws(FileKeystoreException::class) constructor(
    internal val directory: File
) {
    init {
        if (!directory.isAbsolute) {
            throw FileKeystoreException(
                "Root directory must use an absolute path (got '${directory.path}')"
            )
        }
        if (directory.exists()) {
            if (!directory.isDirectory) {
                throw FileKeystoreException("Root '${directory.path}' isn't a directory")
            }

            // Check permissions (read and write operations are always allowed on Windows)
            if (!directory.canRead()) {
                throw FileKeystoreException("Root '${directory.path}' isn't readable")
            }
            if (!directory.canWrite()) {
                throw FileKeystoreException("Root '${directory.path}' isn't writable")
            }
        }
    }
}
