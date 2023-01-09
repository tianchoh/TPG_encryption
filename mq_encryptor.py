from base64 import b16encode
from Cryptodome.Cipher import AES
from Padding import appendPadding
from src.commons.logging import create_logger
from src.encryption.commons import *
from src.encryption.mqutils import MQEncryptorUtils



logger = create_logger(__name__)


def mq_encode_string(string_to_encode: str, current_date: str, transaction_id: str, otp: str, nonce: bytes) -> dict:
    """
    Encodes a given string using the AES-128 encryption algorithm. This is the intended entry point of the encryption
    module. Apart from the string to encode, the other two parameters are used as part of the encryption key generation.
    A random OTP should also have been privately generated and used as part of the key. The output object includes the
    resultant ciphertext and tag of the encryption, as well as the nonce used in the encryption process.
    :param string_to_encode: The string to be encoded.
    :param current_date: The current date, as a string.
    :param transaction_id: The transaction ID of the transaction, as a string.
    :param otp: The OTP generated previously by this program. This should not be the OTP sent by the user.
    :return: A JSON-encoded string containing the encrypted data.
    """
    encryptor = MQEncryptor(current_date=current_date, transaction_id=transaction_id, otp=otp, nonce=nonce)

    return encryptor._mq_encode_string(string_to_encode=string_to_encode)


class MQEncryptor:
    """
    Represents a one-time use object for encryption. The core of the encryption process is the AES-128 algorithm,
    implemented using the PyCryptoDome module. A separate Encryptor object should be created for each individual
    encryption of a string. The Encryptor class should not be accessed directly; it should only be accessed via the
    encode_object() method outside this class.
    """
    __current_date: str = None
    __transaction_id: str = None
    __otp: str = None
    __encryption_key: str = None
    __nonce: bytes = None

    def __init__(self, current_date, transaction_id, otp, nonce):
        self.__current_date = current_date
        self.__transaction_id = transaction_id
        self.__otp = otp
        self.__encryption_key = MQEncryptorUtils.generate_mq_encryption_key_from_fields(current_date=self.__current_date,
                                                                                   transaction_id=self.__transaction_id,
                                                                                   otp=self.__otp)
        self.__nonce = nonce

    def _mq_encode_string(self, string_to_encode: str) -> dict:
        """
        Encodes a given string. The encryption key used in this encryption must have been initialized with this object.
        The encoding of the string takes 3 processes:
        1) The string is converted into hex values,
        2) The string is appropriately padded (following the RFC 5652 Section 6.3 protocol),
        3) The string is encrypted using the AES-128 algorithm.

        A suitable decryption method should therefore implement the reverse functions of all three methods. A reference
        for this decryption process can be found in the test folder for this class.

        :param string_to_encode: The string to encode.
        :return: A dictionary containing the ciphertext, tag, and nonce for the encryption.
        """
        logger.info("Input string to encode: <{}>".format(string_to_encode))

        hex_string = _convert_string_to_hex(string_to_convert=string_to_encode)

        # padded_string = _pad_string(string_to_pad=hex_string)

        ciphertext, tag, nonce = self._mq_encrypt_string(string_to_encrypt=string_to_encode)

        output = MQEncryptorUtils.output_as_dict([ciphertext, tag, nonce])
        return output

    def _mq_encrypt_string(self, string_to_encrypt: str) -> (str, str, str):
        """
        Encrypts a given string using the AES-128 algorithm. The encryption key used in this method must have been
        initialized to this object already; otherwise this method will fail.
        :param string_to_encrypt: The input string to be encrypted.
        :return: Returns a tuple of 3 strings, representing the ciphertext, tag, and nonce used in the encryption.
        """
        assert self.__encryption_key is not None, "Encryption key is not initialized."

        encryption_key = bytes.fromhex(self.__encryption_key)

        bytes_to_encrypt = bytes(string_to_encrypt.encode())
        

        cipher = AES.new(encryption_key, AES.MODE_CCM, self.__nonce)
        ciphertext, tag = cipher.encrypt_and_digest(bytes_to_encrypt)
        ciphertext_string = ciphertext.hex()
        tag_string = tag.hex()
        nonce_string = self.__nonce.decode()

        logger.info("Output ciphertext: <{}>".format(ciphertext_string))
        logger.info("Output tag: <{}>".format(tag_string))
        logger.info("Nonce used: <{}>".format(nonce_string))

        return ciphertext_string, tag_string, nonce_string


def _convert_string_to_hex(string_to_convert: str) -> str:
    """
    Converts a string to its hex value. Uses the helper function from the EncryptorUtils class.
    :param string_to_convert: The input string to convert into hex values.
    :return: The converted string as hex values.
    """
    input_string_as_hex_values = MQEncryptorUtils.convert_string_to_hex_string(string_to_convert=string_to_convert)
    return input_string_as_hex_values


def _pad_string(string_to_pad: str) -> str:
    """
    Pads a string to the appropriate block length. Uses the protocol set out in RFC 5652 Section 6.3.
    :param string_to_pad: The input string to be padded.
    :return: The padded string.
    """
    padded_string = appendPadding(str=string_to_pad)
    logger.debug("Padded original string <{}> to padded string <{}> using PKCS#7 protocol"
                 .format(string_to_pad, padded_string))
    return padded_string
