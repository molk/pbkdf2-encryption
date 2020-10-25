import spock.lang.Specification

import static PBKDF2Encryption.decodeAndDecrypt
import static PBKDF2Encryption.encryptAndEncode

class PBKDF2EncryptionTest extends Specification {

    def 'encrypt and decrypt' () {
        given:
        def plainText = 'encrypt me'

        when: 'encrypting a plain text'
        def encrypted = encryptAndEncode plainText

        and: 'decrypting the encrypted values'
        def decrypted = decodeAndDecrypt encrypted

        then: 'the decrypted value should be the same as the plain text'
        decrypted == plainText
    }

}
