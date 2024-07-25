package tech.relaycorp.awala.keystores.file

import java.io.File
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import tech.relaycorp.relaynet.keystores.PrivateKeyData
import tech.relaycorp.relaynet.keystores.PrivateKeyStore

public abstract class FilePrivateKeyStore(
    keystoreRoot: FileKeystoreRoot,
) : PrivateKeyStore() {
    @Suppress("MemberVisibilityCanBePrivate")
    public val rootDirectory: File = keystoreRoot.directory.resolve("private")

    @Suppress("BlockingMethodInNonBlockingContext")
    override suspend fun saveIdentityKeyData(
        nodeId: String,
        keyData: PrivateKeyData,
    ) {
        val keyFile = getNodeSubdirectory(nodeId).resolve("identity")
        saveKeyFile(keyFile, keyData.privateKeyDer)
    }

    override suspend fun retrieveIdentityKeyData(nodeId: String): PrivateKeyData? {
        val keyFile = getNodeSubdirectory(nodeId).resolve("identity")
        return retrieveKeyData(keyFile)?.let { PrivateKeyData(it) }
    }

    override suspend fun retrieveAllIdentityKeyData(): List<PrivateKeyData> =
        getNodeDirectories()
            ?.map { it.resolve("identity") }
            ?.mapNotNull { path -> retrieveKeyData(path)?.let { PrivateKeyData(it) } }
            ?: listOf()

    override suspend fun saveSessionKeySerialized(
        keyId: String,
        keySerialized: ByteArray,
        nodeId: String,
        peerId: String?,
    ) {
        val keyFile = resolveSessionKeyFile(nodeId, keyId, peerId)
        saveKeyFile(keyFile, keySerialized)
    }

    override suspend fun retrieveSessionKeySerialized(
        keyId: String,
        nodeId: String,
        peerId: String,
    ): ByteArray? {
        val boundKeyPath = resolveSessionKeyFile(nodeId, keyId, peerId)
        val unboundKeyPath = resolveSessionKeyFile(nodeId, keyId, null)
        return retrieveKeyData(boundKeyPath) ?: retrieveKeyData(unboundKeyPath)
    }

    private fun saveKeyFile(
        keyFile: File,
        serialization: ByteArray,
    ) {
        val parentDirectory = keyFile.parentFile
        val wereDirectoriesCreated = parentDirectory.mkdirs()
        if (!wereDirectoriesCreated && !parentDirectory.exists()) {
            throw FileKeystoreException("Failed to create root directory for private keys")
        }

        try {
            makeEncryptedOutputStream(keyFile).use {
                it.write(serialization)
                it.flush()
            }
        } catch (exc: IOException) {
            throw FileKeystoreException("Failed to save key file", exc)
        }
    }

    private fun retrieveKeyData(keyFile: File): ByteArray? {
        return try {
            makeEncryptedInputStream(keyFile).use { it.readBytes() }
        } catch (exc: IOException) {
            if (keyFile.exists()) {
                throw FileKeystoreException("Failed to read key file", exc)
            }
            return null
        }
    }

    private fun resolveSessionKeyFile(
        nodeId: String,
        keyId: String,
        peerId: String?,
    ): File {
        val nodeSubdirectory = getNodeSubdirectory(nodeId).resolve("session")
        val parentDirectory =
            if (peerId != null) {
                nodeSubdirectory.resolve(peerId)
            } else {
                nodeSubdirectory
            }
        return parentDirectory.resolve(keyId)
    }

    private fun getNodeSubdirectory(nodeId: String) = rootDirectory.resolve(nodeId)

    private fun getNodeDirectories() = rootDirectory.listFiles()?.filter(File::isDirectory)

    protected abstract fun makeEncryptedOutputStream(file: File): OutputStream

    protected abstract fun makeEncryptedInputStream(file: File): InputStream

    /**
     * Delete all the private keys associated with [nodeId].
     */
    @Throws(FileKeystoreException::class)
    override suspend fun deleteKeys(nodeId: String) {
        val deletionSucceeded = getNodeSubdirectory(nodeId).deleteRecursively()
        if (!deletionSucceeded) {
            throw FileKeystoreException("Failed to delete node directory for $nodeId")
        }
    }

    /**
     * Delete all the private keys associated with [peerId].
     */
    @Throws(FileKeystoreException::class)
    override suspend fun deleteBoundSessionKeys(
        nodeId: String,
        peerId: String,
    ) {
        val deletionSucceeded =
            getNodeSubdirectory(nodeId)
                .resolve("session")
                .resolve(peerId)
                .deleteRecursively()
        if (!deletionSucceeded) {
            throw FileKeystoreException(
                "Failed to delete session keys for node $nodeId and peer $peerId",
            )
        }
    }
}
