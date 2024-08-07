package tech.relaycorp.awala.keystores.file

import java.io.File
import java.io.IOException
import java.nio.ByteBuffer
import org.bson.BSONException
import org.bson.BsonBinary
import org.bson.BsonBinaryReader
import org.bson.BsonBinaryWriter
import org.bson.io.BasicOutputBuffer
import tech.relaycorp.relaynet.keystores.SessionPublicKeyData
import tech.relaycorp.relaynet.keystores.SessionPublicKeyStore

public class FileSessionPublicKeystore(
    keystoreRoot: FileKeystoreRoot,
) : SessionPublicKeyStore() {
    @Suppress("MemberVisibilityCanBePrivate")
    public val rootDirectory: File = keystoreRoot.directory.resolve("public")

    override suspend fun saveKeyData(
        keyData: SessionPublicKeyData,
        nodeId: String,
        peerId: String,
    ) {
        val wasDirectoryCreated = rootDirectory.mkdirs()
        if (!wasDirectoryCreated && !rootDirectory.exists()) {
            throw FileKeystoreException("Failed to create root directory for public keys")
        }

        val keyDataFile = getKeyDataFile(nodeId, peerId)
        val bsonSerialization =
            BasicOutputBuffer().use { buffer ->
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

    override suspend fun retrieveKeyData(
        nodeId: String,
        peerId: String,
    ): SessionPublicKeyData? {
        val keyDataFile = getKeyDataFile(nodeId, peerId)
        val serialization =
            try {
                keyDataFile.readBytes()
            } catch (exc: IOException) {
                if (keyDataFile.exists()) {
                    throw FileKeystoreException("Failed to read key file", exc)
                }
                return null
            }
        val data =
            try {
                BsonBinaryReader(ByteBuffer.wrap(serialization)).use {
                    it.readStartDocument()
                    SessionPublicKeyData(
                        it.readBinaryData("key_id").data,
                        it.readBinaryData("key_der").data,
                        it.readInt32("creation_timestamp").toLong(),
                    )
                }
            } catch (exc: BSONException) {
                throw FileKeystoreException("Key file is malformed", exc)
            }
        return data
    }

    override suspend fun delete(
        nodeId: String,
        peerId: String,
    ) {
        val keyDataFile = getKeyDataFile(nodeId, peerId)
        keyDataFile.delete()
    }

    private fun getKeyDataFile(
        nodeId: String,
        peerId: String,
    ) = rootDirectory.resolve("$nodeId-$peerId")
}
