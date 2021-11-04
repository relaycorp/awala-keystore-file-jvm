package tech.relaycorp.awala.keystores.file

import java.io.IOException
import java.nio.file.Path
import kotlin.io.path.createDirectory
import kotlin.io.path.exists
import org.bson.BsonBinary
import org.bson.BsonBinaryWriter
import org.bson.io.BasicOutputBuffer
import tech.relaycorp.relaynet.keystores.SessionPublicKeyData
import tech.relaycorp.relaynet.keystores.SessionPublicKeyStore

public class FileSessionPublicKeystore(
    keystoreRoot: FileKeystoreRoot
) : SessionPublicKeyStore() {
    private val rootDirectory: Path

    init {
        rootDirectory = keystoreRoot.directory.resolve("public")
    }

    override suspend fun saveKeyData(keyData: SessionPublicKeyData, peerPrivateAddress: String) {
        if (!rootDirectory.exists()) {
            try {
                @Suppress("BlockingMethodInNonBlockingContext")
                rootDirectory.createDirectory()
            } catch (exc: IOException) {
                throw FileKeystoreException("Failed to create root directory for public keys", exc)
            }
        }
        val keyDataFile = rootDirectory.resolve(peerPrivateAddress).toFile()
        val bsonSerialization = BasicOutputBuffer().use { buffer ->
            BsonBinaryWriter(buffer).use {
                it.writeStartDocument()
                it.writeBinaryData("key_id", BsonBinary(keyData.keyId))
                it.writeBinaryData("key_der", BsonBinary(keyData.keyDer))
                it.writeInt32("creation_timestamp", keyData.creationTimestamp.toInt())
                it.writeEndDocument()
            }
            buffer.toByteArray()
        }
        try {
            keyDataFile.writeBytes(bsonSerialization)
        } catch (exc: IOException) {
            throw FileKeystoreException("Failed to save key data to file", exc)
        }
    }

    override suspend fun retrieveKeyData(peerPrivateAddress: String): SessionPublicKeyData? {
        return null
    }
}
