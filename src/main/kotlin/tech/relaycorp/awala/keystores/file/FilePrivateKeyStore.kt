package tech.relaycorp.awala.keystores.file

import java.io.File
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.file.FileAlreadyExistsException
import java.nio.file.Path
import kotlin.io.path.createDirectories
import org.bson.BSONException
import org.bson.BsonBinary
import org.bson.BsonBinaryReader
import org.bson.BsonBinaryWriter
import org.bson.io.BasicOutputBuffer
import tech.relaycorp.relaynet.keystores.PrivateKeyData
import tech.relaycorp.relaynet.keystores.PrivateKeyStore

public abstract class FilePrivateKeyStore(keystoreRoot: FileKeystoreRoot) : PrivateKeyStore() {
    private val rootDirectory: Path

    init {
        rootDirectory = keystoreRoot.directory.resolve("private")
    }

    @Suppress("BlockingMethodInNonBlockingContext")
    override suspend fun saveKeyData(
        keyId: String,
        keyData: PrivateKeyData,
        privateAddress: String
    ) {
        val nodeSubdirectory = getNodeSubdirectory(privateAddress)
        try {
            nodeSubdirectory.createDirectories()
        } catch (exc: FileAlreadyExistsException) {
            // Do nothing
        } catch (exc: IOException) {
            throw FileKeystoreException("Failed to create root directory for private keys", exc)
        }
        val keyFile = nodeSubdirectory.resolve(keyId).toFile()
        val bsonSerialization = bsonSerializeKeyData(keyData)
        try {
            makeEncryptedOutputStream(keyFile).use {
                it.write(bsonSerialization)
                it.flush()
            }
        } catch (exc: IOException) {
            throw FileKeystoreException("Failed to save key file", exc)
        }
    }

    override suspend fun retrieveKeyData(keyId: String, privateAddress: String): PrivateKeyData? {
        val keyFile = getNodeSubdirectory(privateAddress).resolve(keyId).toFile()
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

    private fun getNodeSubdirectory(privateAddress: String) =
        rootDirectory.resolve(privateAddress)

    protected abstract fun makeEncryptedOutputStream(file: File): OutputStream

    protected abstract fun makeEncryptedInputStream(file: File): InputStream

    private companion object {
        fun bsonSerializeKeyData(keyData: PrivateKeyData): ByteArray =
            BasicOutputBuffer().use { buffer ->
                BsonBinaryWriter(buffer).use {
                    it.writeStartDocument()
                    it.writeBinaryData("private_key", BsonBinary(keyData.privateKeyDer))
                    it.writeBinaryData(
                        "certificate",
                        BsonBinary(keyData.certificateDer ?: byteArrayOf())
                    )
                    it.writeString("peer_private_address", keyData.peerPrivateAddress ?: "")
                    it.writeEndDocument()
                }
                buffer.toByteArray()
            }

        fun bsonDeserializeKeyData(serialization: ByteArray) =
            BsonBinaryReader(ByteBuffer.wrap(serialization)).use {
                it.readStartDocument()
                val privateKeyDer = it.readBinaryData("private_key").data
                val certificateDer = it.readBinaryData("certificate").data
                val peerPrivateAddress = it.readString("peer_private_address")
                PrivateKeyData(
                    privateKeyDer,
                    if (certificateDer.isNotEmpty()) certificateDer else null,
                    peerPrivateAddress.ifEmpty { null },
                )
            }
    }
}
