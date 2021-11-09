package tech.relaycorp.awala.keystores.file

import java.io.File
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import org.bson.BSONException
import org.bson.BsonBinary
import org.bson.BsonBinaryReader
import org.bson.BsonBinaryWriter
import org.bson.io.BasicOutputBuffer
import tech.relaycorp.relaynet.keystores.IdentityPrivateKeyData
import tech.relaycorp.relaynet.keystores.PrivateKeyData
import tech.relaycorp.relaynet.keystores.PrivateKeyStore

public abstract class FilePrivateKeyStore(keystoreRoot: FileKeystoreRoot) : PrivateKeyStore() {
    private val rootDirectory = keystoreRoot.directory.resolve("private")

    @Suppress("BlockingMethodInNonBlockingContext")
    override suspend fun saveIdentityKeyData(
        privateAddress: String,
        keyData: IdentityPrivateKeyData
    ) {
        val keyFile = getNodeSubdirectory(privateAddress).resolve("IDENTITY")
        saveKeyFile(keyFile) {
            writeBinaryData("private_key", BsonBinary(keyData.privateKeyDer))
            writeBinaryData("certificate", BsonBinary(keyData.certificateDer))
        }
    }

    override suspend fun retrieveIdentityKeyData(privateAddress: String): IdentityPrivateKeyData? {
        val keyFile = getNodeSubdirectory(privateAddress).resolve("IDENTITY")
        return retrieveKeyData(keyFile)?.toIdentityPrivateKeyData()
    }

    override suspend fun retrieveAllIdentityKeyData(): List<IdentityPrivateKeyData> =
        rootDirectory.listFiles()?.filter {
            it.isDirectory && it.resolve("IDENTITY").exists()
        }?.map {
            retrieveKeyData(it.resolve("IDENTITY"))!!.toIdentityPrivateKeyData()
        } ?: listOf()

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

    private fun saveKeyFile(keyFile: File, bsonWriter: BsonBinaryWriter.() -> Unit) {
        saveKeyFile(keyFile, bsonSerializeKeyData(bsonWriter))
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

    protected abstract fun makeEncryptedOutputStream(file: File): OutputStream

    protected abstract fun makeEncryptedInputStream(file: File): InputStream

    private fun ByteArray.toIdentityPrivateKeyData() = bsonDeserializeKeyData(this) {
        val privateKeyDer = readBinaryData("private_key").data
        val certificateDer = readBinaryData("certificate").data
        IdentityPrivateKeyData(privateKeyDer, certificateDer)
    }

    /**
     * Delete all the private keys associated with [privateAddress].
     */
    override suspend fun deleteKeys(privateAddress: String) {
        getNodeSubdirectory(privateAddress).deleteRecursively()
    }

    /**
     * Delete all the private keys associated with [peerPrivateAddress].
     */
    override suspend fun deleteSessionKeysForPeer(peerPrivateAddress: String) {
        TODO("Not yet implemented")
    }

    private companion object {
        fun bsonSerializeKeyData(
            writer: BsonBinaryWriter.() -> Unit
        ): ByteArray =
            BasicOutputBuffer().use { buffer ->
                BsonBinaryWriter(buffer).use {
                    it.writeStartDocument()
                    writer(it)
                    it.writeEndDocument()
                }
                buffer.toByteArray()
            }

        fun <T : PrivateKeyData> bsonDeserializeKeyData(
            serialization: ByteArray,
            reader: BsonBinaryReader.() -> T
        ): T =
            try {
                BsonBinaryReader(ByteBuffer.wrap(serialization)).use {
                    it.readStartDocument()
                    reader(it)
                }
            } catch (exc: BSONException) {
                throw FileKeystoreException("Key file is malformed", exc)
            }
    }
}
