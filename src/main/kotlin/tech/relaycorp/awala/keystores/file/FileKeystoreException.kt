package tech.relaycorp.awala.keystores.file

import tech.relaycorp.relaynet.keystores.KeyStoreBackendException

public class FileKeystoreException(
    message: String,
    cause: Throwable? = null,
) : KeyStoreBackendException(message, cause)
