README
WebTester.py
Owen Lutwyche V00977111

HOW TO RUN:
This program was built and tested on the uvic linux.csc.uvic.ca server. It was confirmed to work there.
The code must be run with:
% python WebTester.py (website address)

EXAMPLE:
% python WebTester.py uvic.ca

OUTPUT:
1. Supports http2: (yes or no, identifies whether the host supports http 2.0)
2. List of Cookies: (lists all cookies in the response header. If there are no cookies, this is blank)
cookie name: (name), expires time: (expiry time); domain name: (domain name)
3. Password-protected: (yes or no, identifies whether the host returned a 'forbidden' code)
