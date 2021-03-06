package tech.relaycorp.awala.keystores.file

import java.io.File
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import tech.relaycorp.relaynet.keystores.PrivateKeyData
import tech.relaycorp.relaynet.keystores.PrivateKeyStore

public abstract class FilePrivateKeyStore(keystoreRoot: FileKeystoreRoot) : PrivateKeyStore() {
    @Suppress("MemberVisibilityCanBePrivate")
    public val rootDirectory: File = keystoreRoot.directory.resolve("private")

    @Suppress("BlockingMethodInNonBlockingContext")
    override suspend fun saveIdentityKeyData(
        privateAddress: String,
        keyData: PrivateKeyData
    ) {
        val keyFile = getNodeSubdirectory(privateAddress).resolve("identity")
        saveKeyFile(keyFile, keyData.privateKeyDer)
    }

    override suspend fun retrieveIdentityKeyData(privateAddress: String): PrivateKeyData? {
        val keyFile = getNodeSubdirectory(privateAddress).resolve("identity")
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
        privateAddress: String,
        peerPrivateAddress: String?,
    ) {
        val keyFile = resolveSessionKeyFile(privateAddress, keyId, peerPrivateAddress)
        saveKeyFile(keyFile, keySerialized)
    }

    override suspend fun retrieveSessionKeySerialized(
        keyId: String,
        privateAddress: String,
        peerPrivateAddress: String,
    ): ByteArray? {
        val boundKeyPath = resolveSessionKeyFile(privateAddress, keyId, peerPrivateAddress)
        val unboundKeyPath = resolveSessionKeyFile(privateAddress, keyId, null)
        return retrieveKeyData(boundKeyPath) ?: retrieveKeyData(unboundKeyPath)
    }

    private fun saveKeyFile(keyFile: File, serialization: ByteArray) {
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
        privateAddress: String,
        keyId: String,
        peerPrivateAddress: String?
    ): File {
        val nodeSubdirectory = getNodeSubdirectory(privateAddress).resolve("session")
        val parentDirectory = if (peerPrivateAddress != null)
            nodeSubdirectory.resolve(peerPrivateAddress)
        else
            nodeSubdirectory
        return parentDirectory.resolve(keyId)
    }

    private fun getNodeSubdirectory(privateAddress: String) =
        rootDirectory.resolve(privateAddress)

    private fun getNodeDirectories() = rootDirectory.listFiles()?.filter(File::isDirectory)

    protected abstract fun makeEncryptedOutputStream(file: File): OutputStream

    protected abstract fun makeEncryptedInputStream(file: File): InputStream

    /**
     * Delete all the private keys associated with [privateAddress].
     */
    @Throws(FileKeystoreException::class)
    override suspend fun deleteKeys(privateAddress: String) {
        val deletionSucceeded = getNodeSubdirectory(privateAddress).deleteRecursively()
        if (!deletionSucceeded) {
            throw FileKeystoreException("Failed to delete node directory for $privateAddress")
        }
    }

    /**
     * Delete all the private keys associated with [peerPrivateAddress].
     */
    @Throws(FileKeystoreException::class)
    override suspend fun deleteSessionKeysForPeer(peerPrivateAddress: String) {
        val deletionSucceeded = getNodeDirectories()
            ?.map { it.resolve("session").resolve(peerPrivateAddress) }
            ?.filter(File::exists)
            ?.map(File::deleteRecursively)
            ?.all { it }
        if (deletionSucceeded == false) {
            throw FileKeystoreException("Failed to delete all keys for peer $peerPrivateAddress")
        }
    }
}
