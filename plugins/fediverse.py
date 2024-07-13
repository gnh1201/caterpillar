#!/usr/bin/python3
#
# fediverse.py
# Fediverse (Mastodon, Misskey, Pleroma, ...) SPAM filter plugin for Caterpillar Proxy
#
# Caterpillar Proxy - The simple and parasitic web proxy with SPAM filter (formerly, php-httpproxy)
# Namyheon Go (Catswords Research) <abuse@catswords.net>
# https://github.com/gnh1201/caterpillar
#
# Created in: 2022-10-06
# Updated in: 2024-07-06
#
import base64
import hashlib
import io
import re
import requests
import os.path

from decouple import config
from PIL import Image

from base import Extension, Logger

logger = Logger(name="fediverse")

try:
    client_encoding = config("CLIENT_ENCODING", default="utf-8")
    truecaptcha_userid = config("TRUECAPTCHA_USERID")  # truecaptcha.org
    truecaptcha_apikey = config("TRUECAPTCHA_APIKEY")  # truecaptcha.org
    dictionary_file = config(
        "DICTIONARY_FILE", default="words_alpha.txt"
    )  # https://github.com/dwyl/english-words
    librey_apiurl = config(
        "LIBREY_APIURL", default="https://search.catswords.net"
    )  # https://github.com/Ahwxorg/librey
except Exception as e:
    logger.error("[*] Invalid configuration", exc_info=e)


class Fediverse(Extension):
    def __init__(self):
        self.type = "filter"  # this is a filter

        # Load data to use KnownWords4 strategy
        # Download data: https://github.com/dwyl/english-words
        self.known_words = []
        if dictionary_file != "" and os.path.isfile(dictionary_file):
            with open(dictionary_file, "r") as file:
                words = file.readlines()
                self.known_words = [
                    word.strip() for word in words if len(word.strip()) > 3
                ]
                logger.info("[*] Data loaded to use KnownWords4 strategy")

    def test(self, filtered, data, webserver, port, scheme, method, url):
        # prevent cache confusing
        if data.find(b"<title>Welcome to nginx!</title>") > -1:
            return True

        # allowed conditions
        if method == b"GET" or url.find(b"/api") > -1:
            return False

        # convert to text
        data_length = len(data)
        text = data.decode(client_encoding, errors="ignore")
        error_rate = (data_length - len(text)) / data_length
        if error_rate > 0.2:  # it is a binary data
            return False

        # check ID with K-Anonymity strategy
        pattern = r"\b(?:(?<=\/@)|(?<=acct:))([a-zA-Z0-9]{10})\b"
        matches = list(set(re.findall(pattern, text)))
        if len(matches) > 0:
            logger.info("[*] Found ID: %s" % (", ".join(matches)))
            try:
                filtered = not all(map(self.pwnedpasswords_test, matches))
            except Exception as e:
                logger.error("[*] K-Anonymity strategy not working!", exc_info=e)
                filtered = True

        # feedback
        if filtered and len(matches) > 0:
            score = 0
            strategies = []

            # check ID with VowelRatio10 strategy
            def vowel_ratio_test(s):
                ratio = self.calculate_vowel_ratio(s)
                return ratio > 0.2 and ratio < 0.8

            if all(map(vowel_ratio_test, matches)):
                score += 1
                strategies.append("VowelRatio10")

            # check ID with Palindrome4 strategy
            if all(map(self.has_palindrome, matches)):
                score += 1
                strategies.append("Palindrome4")

            # check ID with KnownWords4 strategy
            if all(map(self.has_known_word, matches)):
                score += 2
                strategies.append("KnownWords4")

            # check ID with SearchEngine3 strategy
            if librey_apiurl != "" and all(map(self.search_engine_test, matches)):
                score += 1
                strategies.append("SearchEngine3")

            # check ID with RepeatedNumbers3 strategy
            if all(map(self.repeated_numbers_test, matches)):
                score += 1
                strategies.append("RepeatedNumbers3")

            # logging score
            with open("score.log", "a") as file:
                file.write(
                    "%s\t%s\t%s\r\n"
                    % ("+".join(matches), str(score), "+".join(strategies))
                )

            # make decision
            if score > 1:
                filtered = False

        # check an attached images (check images with Not-CAPTCHA strategy)
        if truecaptcha_userid != "" and not filtered and len(matches) > 0:

            def webp_to_png_base64(url):
                try:
                    response = requests.get(url)
                    img = Image.open(io.BytesIO(response.content))
                    img_png = img.convert("RGBA")
                    buffered = io.BytesIO()
                    img_png.save(buffered, format="PNG")
                    encoded_image = base64.b64encode(buffered.getvalue()).decode(
                        client_encoding
                    )
                    return encoded_image
                except:
                    return None

            urls = re.findall(r'https://[^\s"]+\.webp', text)
            if len(urls) > 0:
                for url in urls:
                    if filtered:
                        break

                    logger.info("[*] downloading... %s" % (url))
                    encoded_image = webp_to_png_base64(url)
                    logger.info("[*] downloaded.")
                    if encoded_image:
                        logger.info("[*] solving...")
                        try:
                            solved = self.truecaptcha_solve(encoded_image)
                            if solved:
                                logger.info("[*] solved: %s" % (solved))
                                filtered = filtered or (
                                    solved.lower() in ["ctkpaarr", "spam"]
                                )
                            else:
                                logger.info("[*] not solved")
                        except Exception as e:
                            logger.error(
                                "[*] Not CAPTCHA strategy not working!", exc_info=e
                            )

        return filtered

    # Strategy: K-Anonymity test - use api.pwnedpasswords.com
    def pwnedpasswords_test(self, s):
        # convert to lowercase
        s = s.lower()

        # SHA1 of the password
        p_sha1 = hashlib.sha1(s.encode()).hexdigest()

        # First 5 char of SHA1 for k-anonymity API use
        f5_sha1 = p_sha1[:5]

        # Last 5 char of SHA1 to match API output
        l5_sha1 = p_sha1[-5:]

        # Making GET request using Requests library
        response = requests.get(f"https://api.pwnedpasswords.com/range/{f5_sha1}")

        # Checking if request was successful
        if response.status_code == 200:
            # Parsing response text
            hashes = response.text.split("\r\n")

            # Using list comprehension to find matching hashes
            matching_hashes = [
                line.split(":")[0] for line in hashes if line.endswith(l5_sha1)
            ]

            # If there are matching hashes, return True, else return False
            return bool(matching_hashes)
        else:
            raise Exception(
                "api.pwnedpasswords.com response status: %s"
                % (str(response.status_code))
            )

        return False

    # Strategy: Not-CAPTCHA - use truecaptcha.org
    def truecaptcha_solve(self, encoded_image):
        url = "https://api.apitruecaptcha.org/one/gettext"
        data = {
            "userid": truecaptcha_userid,
            "apikey": truecaptcha_apikey,
            "data": encoded_image,
            "mode": "human",
        }
        response = requests.post(url=url, json=data)

        if response.status_code == 200:
            data = response.json()

            if "error_message" in data:
                print("[*] Error: %s" % (data["error_message"]))
                return None
            if "result" in data:
                return data["result"]
        else:
            raise Exception(
                "api.apitruecaptcha.org response status: %s"
                % (str(response.status_code))
            )

        return None

    # Strategy: VowelRatio10
    def calculate_vowel_ratio(self, s):
        # Calculate the length of the string.
        length = len(s)
        if length == 0:
            return 0.0

        # Count the number of vowels ('a', 'e', 'i', 'o', 'u', 'w', 'y') in the string.
        vowel_count = sum(1 for char in s if char.lower() in "aeiouwy")

        # Define vowel-ending patterns
        vowel_ending_patterns = ["ang", "eng", "ing", "ong", "ung", "ank", "ink", "dge"]

        # Count the occurrences of vowel-ending patterns in the string.
        vowel_count += sum(s.count(pattern) for pattern in vowel_ending_patterns)

        # Calculate the ratio of vowels to the total length of the string.
        vowel_ratio = vowel_count / length

        return vowel_ratio

    # Strategy: Palindrome4
    def has_palindrome(self, input_string):
        def is_palindrome(s):
            return s == s[::-1]

        input_string = input_string.lower()
        n = len(input_string)
        for i in range(n):
            for j in range(i + 4, n + 1):  # Find substrings of at least 5 characters
                substring = input_string[i:j]
                if is_palindrome(substring):
                    return True
        return False

    # Strategy: KnownWords4
    def has_known_word(self, input_string):
        def is_known_word(s):
            return s in self.known_words

        input_string = input_string.lower()
        n = len(input_string)
        for i in range(n):
            for j in range(i + 4, n + 1):  # Find substrings of at least 5 characters
                substring = input_string[i:j]
                if is_known_word(substring):
                    return True
        return False

    # Strategy: SearchEngine3
    def search_engine_test(self, s):
        url = "%s/api.php?q=%s" % (librey_apiurl, s)
        response = requests.get(url, verify=False)
        if response.status_code != 200:
            return False

        data = response.json()

        if "results_source" in data:
            del data["results_source"]

        num_results = len(data)

        return num_results > 2

    # Strategy: RepeatedNumbers3
    def repeated_numbers_test(self, s):
        return bool(re.search(r"\d{3,}", s))
