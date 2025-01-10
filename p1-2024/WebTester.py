'''
Owen Lutwyche V00977111 
WebTester.py
Input: URL of a web server, via stdin.
Output: Information regarding the input web server as follows:
1. whether or not the web server supports http2
2. cookie name, expiry time, and domain name of any cookies the web server will use
3. whether or not the requested web page is password protected

Output Format example:
    website: www.uvic.ca
    1. Supports http2: no
    2. List of Cookies:
    cookie name: SESSID_UV_128004, domain name: www.uvic.ca
    cookie name: uvic_bar, expires time: Thu, 04-Jan-2018 00:00:01 GMT; domain name: .uvic.ca

general outline:
    1. get args (specifically target url)
    2. send a get request to the url
    3. receive the response, or output an error
    4. look through the response and make sure it's as expected
        handle 301/302 errors by requesting from the new location
    5. parse response into readable format and output

'''
import sys
import socket
import ssl
#import certifi
#import requests

version="HTTP/1.1"
list_of_cookies=list()
http2_supported=False
password_protected=False


class Request:
    # represents a simple HTTP request
    def __init__(self, _method, _URL, _version, _host):
        self.method=_method
        self.URL=_URL.strip(" ")
        self.version=_version
        self.host=_host.strip(" ")

    def list(self):
        #lists all self.variables for debugging
        print("method: "+self.method+"\nURL: "+self.URL+"\nversion: "+self.version+"\nhost: "+self.host)

class Cookie:
    # represents a cookie from an HTTP response
    def __init__(self, _name, _expire_time, _domain_name):
        self.name=_name
        self.expire_time=_expire_time
        self.domain_name=_domain_name
        return

    def list(self):
        # prints all relevant attributes of the cookie
        if(self.expire_time!="" and self.domain_name!=""):
            print("cookie name: "+self.name+", expires time: "+self.expire_time+"; domain name: "+self.domain_name)
        elif(self.expire_time=="" and self.domain_name==""):
            print("cookie name: "+self.name)
        elif(self.expire_time==""):
            print("cookie name: "+self.name+", domain name: "+self.domain_name)
        else:
            print("cookie name: "+self.name+", expires time: "+self.expire_time)


def create_cookie(line):
    # make a cookie into an object!
    name=""
    expire_time=""
    domain_name=""
    
    line = line.split(";")
    for var in line:
        # iterate through the line as an array, find the important variables
        #print(var)
        
        if(var.lower().startswith("set-cookie")):
            

            # This may be a 'var=val' statement!
            name = (var.split(" ")[1])

            # remove anything following the '='
            # EXAMPLE: set-cookie: uvic_bar=deleted -> the name is just uvic_bar
            name = name.partition("=")[0]

            #get expiry time and domain name if they are present
        elif(var.lower().startswith(" expires")):
            expire_time=(var.split("=")[1])
        elif(var.lower().startswith(" domain")):
            domain_name=(var.split("=")[1])
            
    #define the cookie object
    cookie = Cookie(name, expire_time, domain_name)
    #cookie.list()
    return cookie


class Response_Headers:
    
    def __init__(self, _version, _code, _phrase, _headers, _cookies):
        # initializes the object
        self.version=_version
        self.code=_code
        self.phrase=_phrase
        self.headers=_headers
        self.cookies=_cookies
    
    # Set statements for dynamically updating an object
    def set_version(self, _version):
        self.version=_version

    def set_status(self, _code):
        self.code = _code
    
    def set_phrase(self, _phrase):
        self.phrase = _phrase

    def set_headers(self, _headers):
        self.headers=_headers
    def set_cookies(self, _cookies):
        i=0
        for cookie in _cookies:
            # iterate thru the array of cookies, copy them one-by-one
            self.cookies[i]=_cookies[i]
            i+=1

    def list(self):
        #lists all self.variables for debugging
        print("version: "+self.version+"\nStatus: "+self.code+"\nphrase: "+self.phrase)
        print("headers:")
        for line in self.headers:
            print(line)
        return


    def add_cookie(self, cookie):
        # adds a cookie to the list of cookies for easy reference
        self.cookies.append(cookie)
        
        # these are just debug statements
        #self.cookies[len(self.cookies)-1].list()
        #self.print_cookies()
        return

    def get_redirect_header(self):
        # find the header that redirects to a new location
        new_url="EMPTY"
        for line in self.headers:
            line_array=line.partition(':')
            #print(line_array)
            # find the redirect address
            if(line_array[0]=="location" or line_array[0]=="Location"):
                #print(new_url)
                new_url = line_array[2]
                #remove the 'https://'
                # this is a bit paranoid
                #print("stripping down "+new_url)
                new_url=new_url.strip()
                new_url=new_url.replace('https://','')
                new_url=new_url.replace('http://','')
                new_url=new_url.replace('\n','')
                new_url=new_url.replace("\\r","") 
                
                print("redirect to: "+new_url)
                
        

                return new_url
        # otherwise it's an error
        #print("No Redirect found!")
        #sys.exit(1)
    
    def print_cookies(self):
        #print all the cookies in the headers!
        i=0
        while(i<len(self.cookies)):
            #print("cookie #"+str(i))
            self.cookies[i].list()
            i+=1
        return


def create_request_object(input_string):
    # returns a Request object given a link
    # split the string at '/', first half is the host, second half is the index/page
    
    input_string = str(input_string)
    #print("redirect string: ", input_string)
    # remove any pesky 'https' messing up our string
    new_url=input_string.strip()
    new_url=new_url.replace('https://','')
    new_url=new_url.replace('http://','')
    new_url=new_url.replace('\n','')
    new_url=new_url.replace('\r','')
    new_url=new_url.replace(':443','')
    new_url=new_url.replace(':80','')
    # disassemble the input string
    input_string_par=str(new_url).partition("/")
    target_host=input_string_par[0]
    URL=input_string_par[2]
    #print("url: ", URL)
    
    # create a request object
    request = Request("GET", URL, version, target_host)
   # print(request.list())
    

    return request


def check_http2_support(request):
    # makes a request with the 'h2' alpn protocol to determine if a site supports http2.
    target_port=443
    target_host=request.host
    supported=False
    context_http2_checker = ssl.create_default_context()
    # ask for http2
    context_http2_checker.set_alpn_protocols(['http/1.1','h2'])
    client_http2_checker = context_http2_checker.wrap_socket(socket.socket(socket.AF_INET), server_hostname=request.host)
    #print("checking http2 support for ")
    #request.list()
    # disabled the error statements so as not to pollute output if the rest works correctly
    try:
        client_http2_checker.connect((request.host, 443))
    except:
        print("failed to connect to host for http2 request")
        sys.exit(1)
    try:
        client_http2_checker.send("GET / HTTP/1.1\r\n\r\n".encode())
    
    except:
        print("failed to send request to host for http2")
        sys.exit(1)
    
    # isolate the alpn protocol
    try:
        h2 = client_http2_checker.selected_alpn_protocol()
    
        if (client_http2_checker.selected_alpn_protocol()=='h2'):
        # the response shows that http2 was chosen
            supported=True
    except:
        print("h2 protocol unreadable")
        sys.exit(1)
    #print("value of http2: ",http2_supported)
    return supported


def get_response_https(request):
    # attempts a GET request with HTTPS and returns the response
    response=b''
    target_host=request.host
    target_port=443
    
    # CHECK HTTP2 SUPPORT USING A SEPARATE CONTEXT
    
    #MAKE THE NORMAL HTTPS REQUEST
    
    client=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        #print("connecting to ", target_host)
        client.connect((target_host, target_port))
    except: 
        print("connection to host failed, host name invalid")
        sys.exit(1)
    context = ssl.create_default_context()
    try:
        client = context.wrap_socket(client, server_hostname=target_host)
        client.send(("GET /"+request.URL+" HTTP/1.1\r\nHost: "+target_host+"\r\n\r\n").encode())
    except:
        # this is goofy but try sending with just http
        #print("client failed to send")
        #sys.exit(1)
        try:
            # check if it only supports http unsecured
            client=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect((target_host, target_port))
            context=ssl.create_default_context()
            client.send(("GET /"+request.URL+" HTTP/1.1\r\nHost: "+target_host+"\r\n\r\n").encode())
        except:
            print("client failed to send http and https")
            sys.exit(1)
    try:
        response += client.recv(16384)
        
        client.close()
    except:
        print("client failed to receive")
        sys.exit(1)

   # check that we actually got something 
    if(response==""):
        print("no response from host")
        sys.exit(1)
    #response = repr(response)
    # print(response)
    #print("ATTEMPT COMPLETE")
    return str(response)


def create_response_headers_object(response_string):
    # creates an object out of http response title and headers
    response = Response_Headers("", "", "", "", [])
    line = 0
    response_string=str(response_string)
    # split it into a traversible array
    response_string_lines = response_string.split('\\n')
    #print("response string lines:")
    #print(response_string_lines) 
    #parse the first line: version status phrase
    top_line = response_string_lines[line].split()
    version = top_line[0]
    status = top_line[1]
    phrase = top_line[2]
    #print("version: "+version)
    #print("status: "+status)
    #print("phrase: "+phrase)
    headers=list()
    response.set_version(version)
    response.set_status(status)
    response.set_phrase(phrase)
   # if(int(response.code)==403):
        #print("forbidden")
       # return response
    # traverse all headers to search for cookies
    while(line<len(response_string_lines) and response_string_lines[line]!="\r"):
         
        #add it to the list of headers just in case we need it
        this_line = response_string_lines[line]
        headers.append(this_line)
        
        #print(this_line)
        this_line.replace('\\r', '')
        if (this_line.lower().startswith('set-cookie')):
            # we have found a cookie, add it to the response object
            response.add_cookie(create_cookie(this_line))
        line+=1
        
    # set parameters of the response object
    response.set_version(version)
    response.set_status(status)
    response.set_phrase(phrase)
    response.set_headers(headers)
    
    #response.print_cookies()
   # print(response.list())
    return response


def main():
    password_protected=False    #flags Unauthorized/Forbidden 
    http2_supported=False    # flags whether the http2 check returned true
    try:
    # get target URL from args
        target_url = sys.argv[1]
    except:
        print("please enter a valid URL")
        sys.exit(1)
    

    # form a request object for the given URL
    request = create_request_object(target_url)

    # send the request and get a response
    response_string = get_response_https(request)
    
    # parse the response into an object
    response = create_response_headers_object(response_string)
    
    #response.print_cookies()
    
    # check whether http2 is supported
    #try:
    http2_supported = check_http2_support(request)
    #except:
    #    http2_supported=False

    code = int(response.code)
    
    # check whether the code necessitates a redirect
    while(code==301 or code==302):
        #print("Redirected!")
        
        # extract URL from response headers, then retry
        redirect_url=response.get_redirect_header()
        if(redirect_url.startswith("/")):
            # need to tack on the old url lol
            redirect_url = request.host+redirect_url
            # WE GOT IT!
        
        request = create_request_object(redirect_url)
        response_string = get_response_https(request)
        new_response=create_response_headers_object(response_string)
        response=new_response # IT TOOK 3 HOURS TO FIND THIS
        code=int(new_response.code)
        
        # this is flawless code and will never loop indefinitely as long as the server is configured correctly

        try:
            http2_supporter=check_http2_support(request)
        except:
            http2_supported=False
    if(code==401 or code==403):
        #print("Unauthorized")
        # set password_protected flag
        password_protected=True
    elif(code==404):
        print("Bad Request")
    
    #print("----------------------RESULTS HERE-----------------------------------")
    #print the response!
    print("website: "+target_url)
    if(http2_supported):
        print("1. Supports http2: yes")
    else:
        print("1. Supports http2: no")
    print("2. List of Cookies:")
    response.print_cookies()
    if(password_protected):
        print("3. Password-protected: yes")
    else:
        print("3. Password-protected: no")


if __name__=='__main__':
    main()

