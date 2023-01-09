from math import pow
from os import urandom
from src.commons.logging import create_logger
from src.commons.messages import *
from src.encryption.commons import *
from src.encryption.utils import EncryptorUtils
from src.test_utils.sms_helper import SMSHelper
from struct import unpack
from urllib.parse import quote
from urllib.request import Request, urlopen
import requests
import json
from requests.auth import HTTPBasicAuth
import datetime

logger = create_logger(__name__)

def getTimeStamp():
    out = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    return out


class OTP:
    @staticmethod
    def generate_otp(mobile_number: str) -> str:
        """
        Generates an OTP and sends it to the user.
        :return: Returns the generated OTP value, as a string.
        """
        otp = _generate_otp()
        _send_otp_to_user(otp=otp, mobile_number=mobile_number)
        return otp, getTimeStamp()


def _generate_otp() -> str:
    """
    Generates a random string of 6 digits. The range of values is "000000" to "999999". This function uses the
    cryptographically-secure implementation of os.urandom() to generate random bytes.
    :return: Returns a random string of 6 digits.
    """
    # Generate 4 random bytes
    random_bytes = urandom(4)

    # Represent the random bytes as an integer
    random_integer = unpack('I', random_bytes)[0]

    # Take the modulus of the random integer to get the last X digits
    random_integer_mod = random_integer % (int(pow(10, GENERATED_OTP_LENGTH)))

    # Pad the string out with zeroes as necessary
    random_six_digit_integer = EncryptorUtils.pad_string_to_length_with_zeroes(str(random_integer_mod),
                                                                               GENERATED_OTP_LENGTH)

    logger.info("Generated OTP <{}>".format(random_six_digit_integer))
    return random_six_digit_integer


def _send_otp_to_user(otp: str, mobile_number: str) -> None:
    """
    TODO: Use the TPG API to send an SMS to the user.
    Sends an OTP to the user via an SMS. The current implementation uses the onewaysms service, and should be replaced
    at a later stage. Additionally, this utilizes the SMSHelper class as part of the Postman testing framework. During
    testing, the method _send_message_via_api should be commented out. Generally, the SMSHelper.set_otp method will not
    need to be commented-out, except for security concerns or performance issues in production.
    :param otp: The OTP to send to the user.
    :param mobile_number: The mobile number to send the message to, which must contain both the country code and actual
    mobile number.
    """
    SMSHelper.set_otp(mobile_number=mobile_number, new_otp=otp)
    _send_message_via_api(otp=otp, mobile_number=mobile_number)


def _send_message_via_api(otp: str, mobile_number: str) -> None:
    """
    A placeholder function that sends an SMS to the user using the onewaysms API. The message templates used in the SMS
    are contained in src.commons.messages.
    :param otp: The OTP to send to the user.
    :param mobile_number: The mobile number to send the message to, which must contain both the country code and actual
    mobile number.
    """
    message = MESSAGE_SENT_VIA_OTP.format(otp)
    message_intl = MESSAGE_SENT_VIA_OTP_INTL.format(otp)
    parsed_message = quote(message, safe="")
    parsed_mobile_number = parse_mobile_number(mobile_number=mobile_number)

    logger.info("Message to send: <{}>".format(message))

    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
    }
    if parsed_mobile_number[0:3] == "+65":
        data = {
            "content": message,
            "to":parsed_mobile_number[1:]
        }
    else:
        data = {
            "content":message_intl,
            "to":parsed_mobile_number[1:]
        }

    data_string = json.dumps(data)
    print("data", data)    
    response = requests.post(API_URL, headers=headers, data = data_string, auth=(API_USERNAME, API_PASSWORD))
    print("sms response", response)

    # logger.info("Status of OTP message: {}".format(response))


def parse_mobile_number(mobile_number: str) -> str:
    """
    Parses the user's phone number from a given number. It is expected that the input mobile number will be of the form
    (country code prefix)-(user phone number). The result should be a direct concatenation of the country code with the
    mobile number, without any hyphen.
    :param mobile_number: The input mobile phone number to parse.
    :return: The user's country prefix concatenated with their phone number.
    """
    return "+" + mobile_number.replace("-", "")
