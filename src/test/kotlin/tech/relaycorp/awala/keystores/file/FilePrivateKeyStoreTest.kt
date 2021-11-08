package tech.relaycorp.awala.keystores.file

import java.time.ZonedDateTime
import kotlin.io.path.createDirectories
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runBlockingTest
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import tech.relaycorp.relaynet.SessionKeyPair
import tech.relaycorp.relaynet.issueEndpointCertificate
import tech.relaycorp.relaynet.keystores.IdentityKeyPair
import tech.relaycorp.relaynet.keystores.MissingKeyException
import tech.relaycorp.relaynet.testing.pki.KeyPairSet
import tech.relaycorp.relaynet.testing.pki.PDACertPath

@ExperimentalCoroutinesApi
@Suppress("BlockingMethodInNonBlockingContext")
class FilePrivateKeyStoreTest : KeystoreTestCase() {
    private val certificate = PDACertPath.PRIVATE_ENDPOINT
    private val privateKey = KeyPairSet.PRIVATE_ENDPOINT.private
    private val privateAddress = certificate.subjectPrivateAddress
    private val sessionKeypair = SessionKeyPair.generate()

    private val peerPrivateAddress = PDACertPath.PDA.subjectPrivateAddress

    private val privateKeystoreRootFile = keystoreRoot.directory.resolve("private")
    private val nodeDirectoryPath = privateKeystoreRootFile.resolve(privateAddress).toPath()

    private val identityKeyFilePath = nodeDirectoryPath.resolve("IDENTITY")
    private val sessionKeyFilePath = nodeDirectoryPath.resolve(
        "s-${byteArrayToHex(sessionKeypair.sessionKey.keyId)}"
    )

    @Nested
    inner class SaveIdentity : PrivateKeyStoreSavingTestCase(
        keystoreRoot,
        identityKeyFilePath,
        { saveIdentityKey(privateKey, certificate) }
    ) {

        @Test
        override fun `Private key should be stored`() = runBlockingTest {
            val keystore = MockFilePrivateKeyStore(keystoreRoot)

            keystore.saveIdentityKey(privateKey, certificate)

            val savedKeyData = readKeyData(identityKeyFilePath)
            assertEquals(
                privateKey.encoded.asList(),
                savedKeyData.readBinaryData("private_key").data.asList()
            )
        }

        @Test
        override fun `Existing file should be updated if key already existed`() = runBlockingTest {
            val keystore = MockFilePrivateKeyStore(keystoreRoot)
            keystore.saveIdentityKey(privateKey, certificate)

            // Replace the certificate
            val differentCertificate = issueEndpointCertificate(
                KeyPairSet.PRIVATE_ENDPOINT.public,
                privateKey,
                ZonedDateTime.now().plusMinutes(1)
            )
            keystore.saveIdentityKey(privateKey, differentCertificate)

            val savedKeyData = readKeyData(identityKeyFilePath)
            savedKeyData.readBinaryData("private_key")
            assertEquals(
                differentCertificate.serialize().asList(),
                savedKeyData.readBinaryData("certificate").data.asList()
            )
        }

        @Test
        fun `Certificate should be stored`() = runBlockingTest {
            val keystore = MockFilePrivateKeyStore(keystoreRoot)

            keystore.saveIdentityKey(privateKey, certificate)

            val savedKeyData = readKeyData(identityKeyFilePath)
            savedKeyData.readBinaryData("private_key")
            assertEquals(
                certificate.serialize().asList(),
                savedKeyData.readBinaryData("certificate").data.asList()
            )
        }
    }

    @Nested
    inner class RetrieveIdentity : PrivateKeyStoreRetrievalTestCase(
        keystoreRoot,
        identityKeyFilePath,
        { retrieveIdentityKey(privateAddress) }
    ) {
        @Test
        override fun `Private key should be returned if file exists`() = runBlockingTest {
            val keystore = MockFilePrivateKeyStore(keystoreRoot)
            keystore.saveIdentityKey(privateKey, certificate)

            val key = keystore.retrieveIdentityKey(privateAddress)

            assertEquals(privateKey, key.privateKey)
        }

        @Test
        fun `Certificate should be returned if present`() = runBlockingTest {
            val keystore = MockFilePrivateKeyStore(keystoreRoot)
            keystore.saveIdentityKey(privateKey, certificate)

            val key = keystore.retrieveIdentityKey(privateAddress)

            assertEquals(certificate, key.certificate)
        }
    }

    @Nested
    inner class AllIdentityKeys {
        @Test
        fun `Nothing should be returned if store is empty`() = runBlockingTest {
            val keystore = MockFilePrivateKeyStore(keystoreRoot)

            val allIdentityKeys = keystore.retrieveAllIdentityKeys()

            assertEquals(0, allIdentityKeys.size)
        }

        @Test
        fun `All identity key pairs should be returned`() = runBlockingTest {
            val keystore = MockFilePrivateKeyStore(keystoreRoot)
            keystore.saveIdentityKey(privateKey, certificate)
            val extraPrivateKey = KeyPairSet.PDA_GRANTEE.private
            val extraCertificate = PDACertPath.PDA
            keystore.saveIdentityKey(extraPrivateKey, extraCertificate)

            val allIdentityKeys = keystore.retrieveAllIdentityKeys()

            assertEquals(2, allIdentityKeys.size)
            assertContains(allIdentityKeys, IdentityKeyPair(privateKey, certificate))
            assertContains(allIdentityKeys, IdentityKeyPair(extraPrivateKey, extraCertificate))
        }

        @Test
        fun `Irrelevant subdirectories should be ignored`() = runBlockingTest {
            val keystore = MockFilePrivateKeyStore(keystoreRoot)
            keystore.saveIdentityKey(privateKey, certificate)
            privateKeystoreRootFile.resolve("invalid").toPath().createDirectories()

            val allIdentityKeys = keystore.retrieveAllIdentityKeys()

            assertEquals(1, allIdentityKeys.size)
            assertContains(allIdentityKeys, IdentityKeyPair(privateKey, certificate))
        }

        @Test
        fun `Irrelevant files should be ignored`() = runBlockingTest {
            val keystore = MockFilePrivateKeyStore(keystoreRoot)
            keystore.saveIdentityKey(privateKey, certificate)
            privateKeystoreRootFile.resolve("invalid").createNewFile()

            val allIdentityKeys = keystore.retrieveAllIdentityKeys()

            assertEquals(1, allIdentityKeys.size)
            assertContains(allIdentityKeys, IdentityKeyPair(privateKey, certificate))
        }
    }

    @Nested
    inner class SaveSession : PrivateKeyStoreSavingTestCase(
        keystoreRoot,
        sessionKeyFilePath,
        {
            saveSessionKey(
                sessionKeypair.privateKey,
                sessionKeypair.sessionKey.keyId,
                privateAddress
            )
        }
    ) {

        @Test
        override fun `Private key should be stored`() = runBlockingTest {
            val keystore = MockFilePrivateKeyStore(keystoreRoot)

            keystore.saveSessionKey(
                sessionKeypair.privateKey,
                sessionKeypair.sessionKey.keyId,
                privateAddress
            )

            val savedKeyData = readKeyData(sessionKeyFilePath)
            assertEquals(
                sessionKeypair.privateKey.encoded.asList(),
                savedKeyData.readBinaryData("private_key").data.asList()
            )
        }

        @Test
        override fun `Existing file should be updated if key already existed`() = runBlockingTest {
            val keystore = MockFilePrivateKeyStore(keystoreRoot)
            keystore.saveSessionKey(
                sessionKeypair.privateKey,
                sessionKeypair.sessionKey.keyId,
                privateAddress
            )

            // Replace the private key
            val differentSessionKeyPair = SessionKeyPair.generate()
            keystore.saveSessionKey(
                differentSessionKeyPair.privateKey,
                sessionKeypair.sessionKey.keyId,
                privateAddress
            )

            val savedKeyData = readKeyData(sessionKeyFilePath)
            assertEquals(
                differentSessionKeyPair.privateKey.encoded.asList(),
                savedKeyData.readBinaryData("private_key").data.asList()
            )
        }

        @Test
        fun `Peer private address should be stored if present`() = runBlockingTest {
            val keystore = MockFilePrivateKeyStore(keystoreRoot)

            keystore.saveSessionKey(
                sessionKeypair.privateKey,
                sessionKeypair.sessionKey.keyId,
                privateAddress,
                peerPrivateAddress,
            )

            val savedKeyData = readKeyData(sessionKeyFilePath)
            savedKeyData.readBinaryData("private_key")
            assertEquals(peerPrivateAddress, savedKeyData.readString("peer_private_address"))
        }

        @Test
        fun `Peer private address should not be stored if absent`() = runBlockingTest {
            val keystore = MockFilePrivateKeyStore(keystoreRoot)

            keystore.saveSessionKey(
                sessionKeypair.privateKey,
                sessionKeypair.sessionKey.keyId,
                privateAddress,
            )

            val savedKeyData = readKeyData(sessionKeyFilePath)
            savedKeyData.readBinaryData("private_key")
            assertEquals("", savedKeyData.readString("peer_private_address"))
        }
    }

    @Nested
    inner class RetrieveSession : PrivateKeyStoreRetrievalTestCase(
        keystoreRoot,
        sessionKeyFilePath,
        {
            retrieveSessionKey(
                sessionKeypair.sessionKey.keyId,
                privateAddress,
                peerPrivateAddress
            )
        }
    ) {
        override fun `Private key should be returned if file exists`() = runBlockingTest {
            val keystore = MockFilePrivateKeyStore(keystoreRoot)
            keystore.saveSessionKey(
                sessionKeypair.privateKey,
                sessionKeypair.sessionKey.keyId,
                privateAddress
            )

            val sessionPrivateKey = keystore.retrieveSessionKey(
                sessionKeypair.sessionKey.keyId,
                privateAddress,
                peerPrivateAddress
            )

            assertEquals(sessionKeypair.privateKey, sessionPrivateKey)
        }

        @Test
        fun `Peer private address should be returned if present`() = runBlockingTest {
            val keystore = MockFilePrivateKeyStore(keystoreRoot)
            keystore.saveSessionKey(
                sessionKeypair.privateKey,
                sessionKeypair.sessionKey.keyId,
                privateAddress,
                peerPrivateAddress
            )

            // Check that the key is bound to the peer
            keystore.retrieveSessionKey(
                sessionKeypair.sessionKey.keyId,
                privateAddress,
                peerPrivateAddress
            )
            assertThrows<MissingKeyException> {
                keystore.retrieveSessionKey(
                    sessionKeypair.sessionKey.keyId,
                    privateAddress,
                    "not $peerPrivateAddress"
                )
            }
        }

        @Test
        fun `Peer private address should not be returned if absent`() = runBlockingTest {
            val keystore = MockFilePrivateKeyStore(keystoreRoot)
            keystore.saveSessionKey(
                sessionKeypair.privateKey,
                sessionKeypair.sessionKey.keyId,
                privateAddress,
            )

            // Check that the key is unbound
            keystore.retrieveSessionKey(
                sessionKeypair.sessionKey.keyId,
                privateAddress,
                peerPrivateAddress
            )
            keystore.retrieveSessionKey(
                sessionKeypair.sessionKey.keyId,
                privateAddress,
                "not $peerPrivateAddress"
            )
        }
    }

    private fun byteArrayToHex(byteArray: ByteArray) =
        byteArray.joinToString("") { "%02x".format(it) }
}
