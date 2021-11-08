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
        val keyFile = getNodeSubdirectory(privateAddress).resolve("IDENTITY")
        return retrieveKeyData(keyFile)?.toIdentityPrivateKeyData()
    }

    override suspend fun retrieveAllIdentityKeyData(): List<IdentityPrivateKeyData> =
        rootDirectory.listFiles()?.filter {
            it.isDirectory && it.resolve("IDENTITY").exists()
        }?.map {
            retrieveKeyData(it.resolve("IDENTITY"))!!.toIdentityPrivateKeyData()
        } ?: listOf()

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
        val keyFile = getNodeSubdirectory(privateAddress).resolve("s-$keyId")
        val serialization = retrieveKeyData(keyFile) ?: return null
        return bsonDeserializeKeyData(serialization) {
            val privateKeyDer = readBinaryData("private_key").data
            val peerPrivateAddress = readString("peer_private_address")
            SessionPrivateKeyData(
                privateKeyDer,
                if (peerPrivateAddress != "") peerPrivateAddress else null
            )
        }
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

    private fun getNodeSubdirectory(privateAddress: String) =
        rootDirectory.resolve(privateAddress)

    protected abstract fun makeEncryptedOutputStream(file: File): OutputStream

    protected abstract fun makeEncryptedInputStream(file: File): InputStream

    private fun ByteArray.toIdentityPrivateKeyData() = bsonDeserializeKeyData(this) {
        val privateKeyDer = readBinaryData("private_key").data
        val certificateDer = readBinaryData("certificate").data
        IdentityPrivateKeyData(privateKeyDer, certificateDer)
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
