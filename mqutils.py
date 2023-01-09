from src.commons.logging import create_logger
from src.encryption.commons import *


logger = create_logger(__name__)


class MQEncryptorUtils:
    @staticmethod
    def generate_mq_encryption_key_from_fields(current_date: str, transaction_id: str, otp: str) -> str:
        """
        Generates an encryption key from input fields. The encryption key is a concatenation of hex strings of the three
        input fields; specifically:
        1) The day and month of the current date as a hex string,
        2) The padded string of the transaction_id field,
        3) The OTP as a padded hex string.
        :param current_date: One of the three required input parameters.
        :param transaction_id: One of the three required input parameters.
        :param otp: One of the three required input parameters.
        :return: The generated encryption key, as a string.
        """
        day_and_month = current_date[0:4]
        hex_current_date = MQEncryptorUtils._convert_integer_string_to_hex_value(integer_string_to_convert=day_and_month)
        #padded_hex_current_date = MQEncryptorUtils.pad_string_to_length_with_zeroes(string_to_pad=hex_current_date,
        #                                                                          padded_length=KEY_DATE_HEX_LENGTH)

        #padded_transaction_id = MQEncryptorUtils.pad_string_to_length_with_zeroes(
        #    string_to_pad=transaction_id, padded_length=KEY_TRANSACTION_ID_HEX_LENGTH)

        hex_otp = MQEncryptorUtils._convert_integer_string_to_hex_value(integer_string_to_convert=otp)
        #padded_hex_otp = MQEncryptorUtils.pad_string_to_length_with_zeroes(string_to_pad=hex_otp,
        #                                                                 padded_length=KEY_OTP_HEX_LENGTH)

        encryption_key = "".join([hex_current_date, transaction_id, hex_otp])
        logger.debug("Generated encryption key: <{}>".format(encryption_key))
        return encryption_key

    @staticmethod
    def convert_string_to_hex_string(string_to_convert: str) -> str:
        """
        Converts a string to its hex value equivalent. Each character in the string is converted to its equivalent
        ASCII value, which is then converted into its hexadecimal representation.
        :param string_to_convert: The string to be converted into hex value.
        :return: The hex values of the input string, as a string.
        """
        string_converted_to_bytes = string_to_convert.encode(encoding=BYTES_ENCODING_FORMAT)
        string_converted_to_hex = str(string_converted_to_bytes.hex())
        logger.debug("Converted original string <{}> to hex values <{}>".format(string_to_convert,
                                                                                string_converted_to_hex))
        return string_converted_to_hex

    @staticmethod
    def pad_string_to_length_with_zeroes(string_to_pad: str, padded_length: int) -> str:
        """
        Pads a string with '0's on the left until the desired length is reached. If the input string length exceeds the
        desired padded length, an IndexError is raised.
        :param string_to_pad: The input string to pad with '0's.
        :param padded_length: The desired length of the padded string.
        :return: The padded string. An IndexError is raised if input string length exceeds the desired padded length.
        """
        if len(string_to_pad) > padded_length:
            raise IndexError("Input string length <{}> exceeds desired padded length <{}>."
                             .format(len(string_to_pad), padded_length))

        padded_string = string_to_pad.rjust(padded_length, "0")

        logger.debug("Padded original string <{}> to padded string <{}> using leading 0s"
                     .format(string_to_pad, padded_string))
        return padded_string

    @staticmethod
    def _convert_integer_string_to_hex_value(integer_string_to_convert: str) -> str:
        """
        Converts a string to its hex value. The hex characters will be in uppercase, and the resultant string will not
        have the "0x" prefix. This method is distinct from the method convert_string_to_hex_string() as this uses the
        actual integer value for conversion, rather than the ASCII table value.
        :param integer_string_to_convert: The input string to convert into hex value.
        :return: A hex value as string, in uppercase.
        """
        hex_value = format(int(integer_string_to_convert), 'X')
        logger.debug("Converted original string <{}> to hex value <{}>".format(integer_string_to_convert, hex_value))
        return hex_value

    @staticmethod
    def output_as_dict(values: list) -> dict:
        """
        Generates a dictionary with the input values. The keys used are found in the commons file.
        :param values: The input values to be assigned to the dictionary
        :return: The dictionary representing all required keys and values.
        """
        json_keys = JSON_KEYS_FORMAT
        output_dictionary = dict(zip(json_keys, values))
        return output_dictionary
