package tech.relaycorp.awala.keystores.file

import java.io.File
import tech.relaycorp.relaynet.keystores.SessionPublicKeyData
import tech.relaycorp.relaynet.keystores.SessionPublicKeyStore

public class FileSessionPublicKeyStore(
    private val rootDirectory: File
) : SessionPublicKeyStore() {
    override suspend fun saveKeyData(keyData: SessionPublicKeyData, peerPrivateAddress: String) {
        TODO("Not yet implemented")
    }

    override suspend fun retrieveKeyData(peerPrivateAddress: String): SessionPublicKeyData? {
        TODO("Not yet implemented")
    }
}
