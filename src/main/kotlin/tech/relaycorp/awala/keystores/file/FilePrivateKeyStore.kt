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
import tech.relaycorp.relaynet.keystores.SessionPrivateKeyData

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
        TODO("Not yet implemented")
    }

    public suspend fun retrieveKeyData(keyId: String, privateAddress: String): PrivateKeyData? {
        val keyFile = getNodeSubdirectory(privateAddress).resolve(keyId)
        val serialization = try {
            makeEncryptedInputStream(keyFile).use { it.readBytes() }
        } catch (exc: IOException) {
            if (keyFile.exists()) {
                throw FileKeystoreException("Failed to read key file", exc)
            }
            return null
        }
        return try {
            bsonDeserializeKeyData(serialization)
        } catch (exc: BSONException) {
            throw FileKeystoreException("Key file is malformed", exc)
        }
    }

    override suspend fun retrieveAllIdentityKeyData(): List<IdentityPrivateKeyData> {
        TODO("Not yet implemented")
    }

    override suspend fun saveSessionKeyData(
        keyId: String,
        keyData: SessionPrivateKeyData,
        privateAddress: String
    ) {
        val keyFile = getNodeSubdirectory(privateAddress).resolve("s-$keyId")

        saveKeyFile(keyFile) {
            writeBinaryData("private_key", BsonBinary(keyData.privateKeyDer))
            writeString("peer_private_address", keyData.peerPrivateAddress ?: "")
        }
    }

    override suspend fun retrieveSessionKeyData(
        keyId: String,
        privateAddress: String
    ): SessionPrivateKeyData? {
        TODO("Not yet implemented")
    }

    private fun saveKeyFile(keyFile: File, bsonWriter: BsonBinaryWriter.() -> Unit) {
        val parentDirectory = keyFile.parentFile
        val wereDirectoriesCreated = parentDirectory.mkdirs()
        if (!wereDirectoriesCreated && !parentDirectory.exists()) {
            throw FileKeystoreException("Failed to create root directory for private keys")
        }

        try {
            makeEncryptedOutputStream(keyFile).use {
                it.write(bsonSerializeKeyData(bsonWriter))
                it.flush()
            }
        } catch (exc: IOException) {
            throw FileKeystoreException("Failed to save key file", exc)
        }
    }

    private fun getNodeSubdirectory(privateAddress: String) =
        rootDirectory.resolve(privateAddress)

    protected abstract fun makeEncryptedOutputStream(file: File): OutputStream

    protected abstract fun makeEncryptedInputStream(file: File): InputStream

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

        fun bsonDeserializeKeyData(serialization: ByteArray) =
            BsonBinaryReader(ByteBuffer.wrap(serialization)).use {
                it.readStartDocument()
                val privateKeyDer = it.readBinaryData("private_key").data
                val certificateDer = it.readBinaryData("certificate").data
                // val peerPrivateAddress = it.readString("peer_private_address")
                IdentityPrivateKeyData(
                    privateKeyDer,
                    certificateDer,
                )
            }
    }
}
