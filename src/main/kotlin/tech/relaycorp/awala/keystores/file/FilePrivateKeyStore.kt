package tech.relaycorp.awala.keystores.file

import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.nio.file.Path
import kotlin.io.path.createDirectories
import kotlin.io.path.exists
import org.bson.BsonBinary
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
        if (!nodeSubdirectory.exists()) {
            nodeSubdirectory.createDirectories()
        }
        val keyFile = nodeSubdirectory.resolve(keyId).toFile()
        val bsonSerialization = BasicOutputBuffer().use { buffer ->
            BsonBinaryWriter(buffer).use {
                it.writeStartDocument()
                it.writeBinaryData("private_key", BsonBinary(keyData.privateKeyDer))
                it.writeBinaryData(
                    "certificate",
                    BsonBinary(keyData.certificateDer ?: byteArrayOf())
                )
                it.writeEndDocument()
            }
            buffer.toByteArray()
        }
        makeEncryptedOutputStream(keyFile).use {
            it.write(bsonSerialization)
            it.flush()
        }
    }

    override suspend fun retrieveKeyData(keyId: String, privateAddress: String): PrivateKeyData? {
        TODO("Not yet implemented")
    }

    private fun getNodeSubdirectory(privateAddress: String) =
        rootDirectory.resolve(privateAddress)

    protected abstract fun makeEncryptedOutputStream(file: File): OutputStream

    protected abstract fun makeEncryptedInputStream(file: File): InputStream
}
