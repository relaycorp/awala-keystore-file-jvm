package tech.relaycorp.awala.keystores.file

import java.nio.file.Path
import kotlin.io.path.exists
import kotlin.io.path.isDirectory
import kotlin.io.path.isReadable
import kotlin.io.path.isWritable
import kotlin.io.path.pathString
import tech.relaycorp.relaynet.keystores.SessionPublicKeyData
import tech.relaycorp.relaynet.keystores.SessionPublicKeyStore

public class FileSessionPublicKeyStore @Throws(FileKeystoreException::class) constructor(
    private val rootDirectory: Path
) : SessionPublicKeyStore() {
    init {
        if (!rootDirectory.isAbsolute) {
            throw FileKeystoreException(
                "Root directory must use an absolute path (got '${rootDirectory.pathString}')"
            )
        }
        if (!rootDirectory.exists()) {
            throw FileKeystoreException(
                "Root '${rootDirectory.pathString}' doesn't exist"
            )
        }
        if (!rootDirectory.isDirectory()) {
            throw FileKeystoreException("Root '${rootDirectory.pathString}' isn't a directory")
        }
        if (!rootDirectory.isReadable()) {
            throw FileKeystoreException("Root '${rootDirectory.pathString}' isn't readable")
        }
        if (!rootDirectory.isWritable()) {
            throw FileKeystoreException("Root '${rootDirectory.pathString}' isn't writable")
        }
    }

    override suspend fun saveKeyData(keyData: SessionPublicKeyData, peerPrivateAddress: String) {
        TODO("Not yet implemented")
    }

    override suspend fun retrieveKeyData(peerPrivateAddress: String): SessionPublicKeyData? {
        TODO("Not yet implemented")
    }
}
