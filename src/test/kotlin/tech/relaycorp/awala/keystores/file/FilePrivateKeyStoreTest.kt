package tech.relaycorp.awala.keystores.file

import java.nio.file.Path
import kotlin.io.path.createDirectories
import kotlin.io.path.exists
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.condition.DisabledOnOs
import org.junit.jupiter.api.condition.OS
import tech.relaycorp.relaynet.SessionKeyPair
import tech.relaycorp.relaynet.keystores.MissingKeyException
import tech.relaycorp.relaynet.testing.pki.KeyPairSet
import tech.relaycorp.relaynet.testing.pki.PDACertPath
import tech.relaycorp.relaynet.wrappers.nodeId

@ExperimentalCoroutinesApi
@Suppress("BlockingMethodInNonBlockingContext")
class FilePrivateKeyStoreTest : KeystoreTestCase() {
    private val privateKey = KeyPairSet.PRIVATE_ENDPOINT.private
    private val privateId = privateKey.nodeId
    private val sessionKeypair = SessionKeyPair.generate()

    private val peerId = PDACertPath.PDA.subjectId

    private val privateKeystoreRootFile = keystoreRoot.directory.resolve("private")
    private val nodeDirectoryPath = privateKeystoreRootFile.resolve(privateId).toPath()

    private val identityKeyFilePath = nodeDirectoryPath.resolve("identity")
    private val boundSessionKeyFilePath =
        nodeDirectoryPath.resolve("session").resolve(peerId).resolve(
            byteArrayToHex(sessionKeypair.sessionKey.keyId),
        )
    private val unboundSessionKeyFilePath =
        nodeDirectoryPath.resolve("session").resolve(
            byteArrayToHex(sessionKeypair.sessionKey.keyId),
        )

    @Test
    fun `Root directory should be exposed`() {
        val keystore = MockFilePrivateKeyStore(keystoreRoot)

        assertEquals(privateKeystoreRootFile, keystore.rootDirectory)
    }

    @Nested
    inner class SaveIdentity :
        PrivateKeyStoreSavingTestCase(
            keystoreRoot,
            identityKeyFilePath,
            { saveIdentityKey(privateKey) },
        ) {
        @Test
        override fun `Private key should be stored`() =
            runTest {
                val keystore = MockFilePrivateKeyStore(keystoreRoot)

                keystore.saveIdentityKey(privateKey)

                val savedKeyData = readKeyData(identityKeyFilePath)
                assertEquals(
                    privateKey.encoded.asList(),
                    savedKeyData.asList(),
                )
            }

        private fun readKeyData(path: Path) = MockFilePrivateKeyStore.readFile(path.toFile())
    }

    @Nested
    inner class RetrieveIdentity :
        PrivateKeyStoreRetrievalTestCase(
            keystoreRoot,
            identityKeyFilePath,
            { retrieveIdentityKey(privateId) },
        ) {
        @Test
        fun `Exception should be thrown if private key does not exist`() =
            runTest {
                val keystore = MockFilePrivateKeyStore(keystoreRoot)

                val exception =
                    assertThrows<MissingKeyException> {
                        keystore.retrieveIdentityKey(privateId)
                    }

                assertEquals("There is no identity key for $privateId", exception.message)
            }

        @Test
        override fun `Private key should be returned if file exists`() =
            runTest {
                val keystore = MockFilePrivateKeyStore(keystoreRoot)
                keystore.saveIdentityKey(privateKey)

                val key = keystore.retrieveIdentityKey(privateId)

                assertEquals(privateKey, key)
            }
    }

    @Nested
    inner class AllIdentityKeys {
        @Test
        fun `Nothing should be returned if store is empty`() =
            runTest {
                val keystore = MockFilePrivateKeyStore(keystoreRoot)

                val allIdentityKeys = keystore.retrieveAllIdentityKeys()

                assertEquals(0, allIdentityKeys.size)
            }

        @Test
        fun `All identity key pairs should be returned`() =
            runTest {
                val keystore = MockFilePrivateKeyStore(keystoreRoot)
                keystore.saveIdentityKey(privateKey)
                val extraPrivateKey = KeyPairSet.PDA_GRANTEE.private
                keystore.saveIdentityKey(extraPrivateKey)

                val allIdentityKeys = keystore.retrieveAllIdentityKeys()

                assertEquals(2, allIdentityKeys.size)
                assertContains(allIdentityKeys, privateKey)
                assertContains(allIdentityKeys, extraPrivateKey)
            }

        @Test
        fun `Irrelevant subdirectories should be ignored`() =
            runTest {
                val keystore = MockFilePrivateKeyStore(keystoreRoot)
                keystore.saveIdentityKey(privateKey)
                privateKeystoreRootFile.resolve("invalid").toPath().createDirectories()

                val allIdentityKeys = keystore.retrieveAllIdentityKeys()

                assertEquals(1, allIdentityKeys.size)
                assertContains(allIdentityKeys, privateKey)
            }

        @Test
        fun `Irrelevant files should be ignored`() =
            runTest {
                val keystore = MockFilePrivateKeyStore(keystoreRoot)
                keystore.saveIdentityKey(privateKey)
                privateKeystoreRootFile.resolve("invalid").createNewFile()

                val allIdentityKeys = keystore.retrieveAllIdentityKeys()

                assertEquals(1, allIdentityKeys.size)
                assertContains(allIdentityKeys, privateKey)
            }
    }

    @Nested
    inner class SaveSession :
        PrivateKeyStoreSavingTestCase(
            keystoreRoot,
            unboundSessionKeyFilePath,
            {
                saveSessionKey(
                    sessionKeypair.privateKey,
                    sessionKeypair.sessionKey.keyId,
                    privateId,
                )
            },
        ) {
        @Test
        override fun `Private key should be stored`() =
            runTest {
                val keystore = MockFilePrivateKeyStore(keystoreRoot)

                keystore.saveSessionKey(
                    sessionKeypair.privateKey,
                    sessionKeypair.sessionKey.keyId,
                    privateId,
                )

                assertEquals(
                    sessionKeypair.privateKey.encoded.asList(),
                    readKeyData(unboundSessionKeyFilePath).asList(),
                )
            }

        @Test
        fun `Existing file should be updated if key already existed`() =
            runTest {
                val keystore = MockFilePrivateKeyStore(keystoreRoot)
                keystore.saveSessionKey(
                    sessionKeypair.privateKey,
                    sessionKeypair.sessionKey.keyId,
                    privateId,
                )

                // Replace the private key
                val differentSessionKeyPair = SessionKeyPair.generate()
                keystore.saveSessionKey(
                    differentSessionKeyPair.privateKey,
                    sessionKeypair.sessionKey.keyId,
                    privateId,
                )

                assertEquals(
                    differentSessionKeyPair.privateKey.encoded.asList(),
                    readKeyData(unboundSessionKeyFilePath).asList(),
                )
            }

        @Test
        fun `File should be stored under peer subdirectory if key is bound`() =
            runTest {
                val keystore = MockFilePrivateKeyStore(keystoreRoot)

                keystore.saveSessionKey(
                    sessionKeypair.privateKey,
                    sessionKeypair.sessionKey.keyId,
                    privateId,
                    peerId,
                )

                assertEquals(
                    sessionKeypair.privateKey.encoded.asList(),
                    readKeyData(boundSessionKeyFilePath).asList(),
                )
            }

        @Test
        fun `File should not be stored under a peer subdirectory if key is unbound`() =
            runTest {
                val keystore = MockFilePrivateKeyStore(keystoreRoot)

                keystore.saveSessionKey(
                    sessionKeypair.privateKey,
                    sessionKeypair.sessionKey.keyId,
                    privateId,
                )

                assertEquals(
                    sessionKeypair.privateKey.encoded.asList(),
                    readKeyData(unboundSessionKeyFilePath).asList(),
                )
            }

        private fun readKeyData(path: Path) = MockFilePrivateKeyStore.readFile(path.toFile())
    }

    @Nested
    inner class RetrieveSession :
        PrivateKeyStoreRetrievalTestCase(
            keystoreRoot,
            unboundSessionKeyFilePath,
            {
                retrieveSessionKey(
                    sessionKeypair.sessionKey.keyId,
                    privateId,
                    peerId,
                )
            },
        ) {
        override fun `Private key should be returned if file exists`() =
            runTest {
                val keystore = MockFilePrivateKeyStore(keystoreRoot)
                keystore.saveSessionKey(
                    sessionKeypair.privateKey,
                    sessionKeypair.sessionKey.keyId,
                    privateId,
                )

                val sessionPrivateKey =
                    keystore.retrieveSessionKey(
                        sessionKeypair.sessionKey.keyId,
                        privateId,
                        peerId,
                    )

                assertEquals(sessionKeypair.privateKey, sessionPrivateKey)
            }

        @Test
        fun `Bound keys should be retrieved`() =
            runTest {
                val keystore = MockFilePrivateKeyStore(keystoreRoot)
                keystore.saveSessionKey(
                    sessionKeypair.privateKey,
                    sessionKeypair.sessionKey.keyId,
                    privateId,
                    peerId,
                )

                val privateKey =
                    keystore.retrieveSessionKey(
                        sessionKeypair.sessionKey.keyId,
                        privateId,
                        peerId,
                    )

                assertEquals(
                    sessionKeypair.privateKey.encoded.asList(),
                    privateKey.encoded.asList(),
                )
            }

        @Test
        fun `Unbound keys should be retrieved`() =
            runTest {
                val keystore = MockFilePrivateKeyStore(keystoreRoot)
                keystore.saveSessionKey(
                    sessionKeypair.privateKey,
                    sessionKeypair.sessionKey.keyId,
                    privateId,
                )

                val privateKey =
                    keystore.retrieveSessionKey(
                        sessionKeypair.sessionKey.keyId,
                        privateId,
                        peerId,
                    )

                assertEquals(
                    sessionKeypair.privateKey.encoded.asList(),
                    privateKey.encoded.asList(),
                )
            }
    }

    @Nested
    inner class DeleteKeys {
        @Test
        fun `Node directory should be deleted even if it contains keys`() =
            runTest {
                val keystore = MockFilePrivateKeyStore(keystoreRoot)
                keystore.saveIdentityKey(privateKey)
                keystore.saveSessionKey(
                    sessionKeypair.privateKey,
                    sessionKeypair.sessionKey.keyId,
                    privateId,
                )

                keystore.deleteKeys(privateId)

                assertFalse(nodeDirectoryPath.exists())
            }

        @Test
        fun `Other node directories shouldn't be deleted`() =
            runTest {
                val keystore = MockFilePrivateKeyStore(keystoreRoot)
                keystore.saveIdentityKey(privateKey)
                val node2Directory = nodeDirectoryPath.resolveSibling("node2")
                node2Directory.createDirectories()
                val node3Directory = nodeDirectoryPath.resolveSibling("node3")
                node3Directory.createDirectories()

                keystore.deleteKeys(privateId)

                assertTrue(node2Directory.exists())
                assertTrue(node3Directory.exists())
            }

        @Test
        fun `Nothing should happen if the node directory doesn't exist`() =
            runTest {
                assertFalse(nodeDirectoryPath.exists())
                val keystore = MockFilePrivateKeyStore(keystoreRoot)

                keystore.deleteKeys(privateId)

                assertFalse(nodeDirectoryPath.exists())
            }

        @Test
        @DisabledOnOs(OS.WINDOWS)
        fun `Exception should be thrown if node directory couldn't be deleted`() =
            runTest {
                val keystore = MockFilePrivateKeyStore(keystoreRoot)
                keystore.saveIdentityKey(privateKey)
                nodeDirectoryPath.toFile().setWritable(false)

                val exception =
                    assertThrows<FileKeystoreException> { keystore.deleteKeys(privateId) }

                assertEquals(
                    "Failed to delete node directory for $privateId",
                    exception.message,
                )
            }
    }

    @Nested
    inner class DeleteBoundSessionKeys {
        @Test
        fun `Keys linked to peer should not be deleted from other nodes`() =
            runTest {
                val keystore = MockFilePrivateKeyStore(keystoreRoot)
                keystore.saveSessionKey(
                    sessionKeypair.privateKey,
                    sessionKeypair.sessionKey.keyId,
                    privateId,
                    peerId,
                )
                val node2PrivateAddress = "AnotherPrivateAddress"
                keystore.saveSessionKey(
                    sessionKeypair.privateKey,
                    sessionKeypair.sessionKey.keyId,
                    node2PrivateAddress,
                    peerId,
                )
                val boundSessionKey2FilePath =
                    privateKeystoreRootFile
                        .resolve(node2PrivateAddress)
                        .resolve("session")
                        .resolve(peerId)
                        .resolve(byteArrayToHex(sessionKeypair.sessionKey.keyId))
                        .toPath()
                assertTrue(boundSessionKey2FilePath.exists())

                keystore.deleteBoundSessionKeys(privateId, peerId)

                assertFalse(boundSessionKeyFilePath.parent.exists())
                assertTrue(boundSessionKey2FilePath.parent.exists())
            }

        @Test
        fun `Keys linked to other peers should not be deleted`() =
            runTest {
                val keystore = MockFilePrivateKeyStore(keystoreRoot)
                val peer2PrivateAddress = "Peer2Address"
                val peer2SessionKeypair = SessionKeyPair.generate()
                keystore.saveSessionKey(
                    peer2SessionKeypair.privateKey,
                    peer2SessionKeypair.sessionKey.keyId,
                    privateId,
                    peer2PrivateAddress,
                )

                keystore.deleteBoundSessionKeys(privateId, peerId)

                keystore.retrieveSessionKey(
                    peer2SessionKeypair.sessionKey.keyId,
                    privateId,
                    peer2PrivateAddress,
                )
            }

        @Test
        fun `Unbound keys should not be deleted`() =
            runTest {
                val keystore = MockFilePrivateKeyStore(keystoreRoot)
                keystore.saveSessionKey(
                    sessionKeypair.privateKey,
                    sessionKeypair.sessionKey.keyId,
                    privateId,
                    peerId,
                )
                val unboundSessionKeypair = SessionKeyPair.generate()
                keystore.saveSessionKey(
                    unboundSessionKeypair.privateKey,
                    unboundSessionKeypair.sessionKey.keyId,
                    privateId,
                )

                keystore.deleteBoundSessionKeys(privateId, peerId)

                assertThrows<MissingKeyException> {
                    keystore.retrieveSessionKey(
                        sessionKeypair.sessionKey.keyId,
                        privateId,
                        peerId,
                    )
                }
                keystore.retrieveSessionKey(
                    unboundSessionKeypair.sessionKey.keyId,
                    privateId,
                    peerId,
                )
            }

        @Test
        fun `Nothing should happen if the root directory doesn't exist`() =
            runTest {
                val keystore = MockFilePrivateKeyStore(keystoreRoot)

                keystore.deleteBoundSessionKeys(privateId, peerId)
            }

        @Test
        @DisabledOnOs(OS.WINDOWS)
        fun `Exception should be thrown if a directory couldn't be deleted`() =
            runTest {
                val keystore = MockFilePrivateKeyStore(keystoreRoot)
                keystore.saveSessionKey(
                    sessionKeypair.privateKey,
                    sessionKeypair.sessionKey.keyId,
                    privateId,
                    peerId,
                )
                boundSessionKeyFilePath.parent.toFile().setWritable(false)

                val exception =
                    assertThrows<FileKeystoreException> {
                        keystore.deleteBoundSessionKeys(privateId, peerId)
                    }

                assertEquals(
                    "Failed to delete session keys for node $privateId and peer $peerId",
                    exception.message,
                )
            }
    }

    private fun byteArrayToHex(byteArray: ByteArray) =
        byteArray.joinToString("") { "%02x".format(it) }
}
