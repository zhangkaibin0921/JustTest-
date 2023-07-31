import requests
import sys

def checkWaf(url, header="", proxy="", timeout=5, allow_redirects=False):
    payload = '/cdxy.old/.svn/.bashrc/.mdb/.inc/etc/passwd'
    retVal = False
    retVal1 = False
    infoMsg = "checking if the target is protected by\n"
    infoMsg += "some kind of WAF/IPS/IDS\n"
    print(infoMsg)

    try:
        code = requests.get(url, stream=True, headers=header, timeout=timeout, proxies=proxy,
                            allow_redirects=allow_redirects).status_code
        if code != 200:
            retVal = True
    except Exception as e:
        print(e)
        retVal = True

    try:
        code1 = requests.get(url + payload, stream=True, headers=header, timeout=timeout, proxies=proxy,
                             allow_redirects=allow_redirects, verify=False).status_code
        if code1 != 404:
            retVal1 = True
    except Exception as e:
        print(e)
        retVal1 = True

    if retVal:
        warnMsg = 'Target URL not stable\n'
        warnMsg += '[' + str(code) + '] ' + url + '\n'
        print(warnMsg)

        message = "are you sure that you want to\n"
        message += "continue with further fuzzing? [y/N]\n"
        print(message)
        output = input()
        if not output or output[0] not in ("Y", "y"):
            print('User Quit!')
            sys.exit(0)

    if retVal1:
        warnMsg = "heuristics detected that the target\n"
        warnMsg += "is protected by some kind of WAF/IPS/IDS\n"
        print(warnMsg)

        message = "are you sure that you want to\n"
        message += "continue with further fuzzing? [y/N]\n"
        print(message)
        output = input()

        if not output or output[0] not in ("Y", "y"):
            print('User Quit!')
            sys.exit(0)
