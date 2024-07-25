package tech.relaycorp.awala.keystores.file

import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.nio.charset.Charset
import kotlin.test.assertEquals

/**
 * Private key store that claims to encrypt key files.
 *
 * But it doesn't actually encrypt anything.
 */
class MockFilePrivateKeyStore(
    keystoreRoot: FileKeystoreRoot,
) : FilePrivateKeyStore(keystoreRoot) {
    override fun makeEncryptedOutputStream(file: File): OutputStream {
        val stream = file.outputStream()
        stream.write(header)
        return stream
    }

    override fun makeEncryptedInputStream(file: File): InputStream {
        val stream = file.inputStream()
        stream.skip(header.size.toLong())
        return stream
    }

    companion object {
        private val header = "HEADER".toByteArray()
        private val charset = Charset.defaultCharset()

        fun readFile(file: File): ByteArray {
            val fileContents = file.readBytes()
            assertEquals(
                header.toString(charset),
                fileContents.slice(header.indices).toByteArray().toString(charset),
            )
            return fileContents.slice(header.size until fileContents.size).toByteArray()
        }
    }
}
