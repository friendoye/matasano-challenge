import web
import sys
import os
from random import randint

from hmac_sha1 import insecure_compare, hmac_sha1

FILES_DIR = os.path.dirname(__file__)
COMPARISON_DELAY = 50

class SignatureChecker(object):
    file_names = ["foo"]
    signatures = {}
    _key = ""

    def __init__(self):
        if SignatureChecker._key == "":
            SignatureChecker._key = self.gen_key()
            SignatureChecker.signatures = self.make_signatures(
                SignatureChecker.file_names)
            # debugging
            print(SignatureChecker.signatures)

    def gen_key(self):
        chars = [chr(randint(0, 255)) for __ in range(randint(5, 10))] 
        return "".join(chars)

    def make_signatures(self, file_names):
        dictionary = {}
        for file_name in file_names:
            with open(FILES_DIR + "/" + file_name + ".txt") as input_file:
                message = input_file.read()
                dictionary[file_name] = hmac_sha1(message, 
                                                  SignatureChecker._key)
        return dictionary

    def GET(self):
        is_valid = False
        try:
            query = web.ctx.query[1:]
            tokens = query.split('&')
            params = {}
            for token in tokens:
                key, value = token.split('=')
                params[key] = value

            computed_signature = SignatureChecker.signatures[params["file"]]
            retrieved_signature = params["signature"]
            is_valid = insecure_compare(computed_signature, 
                                        retrieved_signature,
                                        COMPARISON_DELAY)
        except KeyError:
            return "Cannot find 'file' and 'singature' params."
        except:
            return "Invalid params."
        finally:            
            if is_valid:
                web.ctx.status = "200 OK"
            else:
                web.ctx.status = "500"


# main block

if __name__ == "__main__":
    # changing port
    sys.argv = sys.argv[:2]
    sys.argv.append("9000")
    #
    __name__ = "{0}.{1}".format(__package__,
                                os.path.basename(__file__)[:-3])
    print(__name__)
    # start server
    urls = ("/test", "SignatureChecker")
    app = web.application(urls, globals())
    app.run()
