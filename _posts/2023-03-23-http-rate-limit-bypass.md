---
title: <img width="50" height="50" alt="front-page port 80-shoopyu" src="https://hashnode.com/utility/r?url=https%3A%2F%2Fcdn.hashnode.com%2Fres%2Fhashnode%2Fimage%2Fupload%2Fv1590555348643%2FpvuMAUpXQ.png%3Fw%3D1200%26h%3D630%26fit%3Dcrop%26crop%3Dentropy%26auto%3Dcompress%2Cformat%26format%3Dwebp%26fm%3Dpng"> HTTP Rate Limit Bypass
date: 2023-03-23 00:00:02 +730
categories: [Resources, bugbounty]
tags: [http-rate-limit-bypass, bugbounty, rate-limiting, bypass] # TAG names should always be lowercase


---


# Bug Bounty Methodology: HTTP Rate Limit Bypass


## Introduction

This write-up explores a bug bounty methodology related to bypassing HTTP rate limiting. The goal is to evade rate limiting restrictions by adding specific headers and changing the IP address for each request. So grab your Burp Suite and let's dive into the technical details!

## Background

Rate limiting is a common defense mechanism implemented by servers to prevent abuse or excessive requests. When the rate limit is exceeded, the server responds with a `429` HTTP status code, indicating `"Too Many Requests."` However, in some cases, it may be possible to bypass this restriction.


sequenceDiagram
    participant Hacker
    participant Server
    participant BurpSuite
    
    Hacker->>BurpSuite: Set up Burp Suite
    Hacker->>BurpSuite: Configure browser proxy
    Hacker->>Server: Send initial request
    BurpSuite->>Server: Intercept request
    Server-->>BurpSuite: Respond with 429 status code, red
    BurpSuite->>Hacker: Intercepted 429 response, red
    
    loop Modify Headers & IP
        Hacker->>BurpSuite: Modify headers and IP, blue
        BurpSuite->>Server: Forward modified request, blue
        Server-->>BurpSuite: Respond with modified response, green
        BurpSuite->>Hacker: Intercept modified response, green
        alt Rate Limit Bypassed?
            Hacker->>Hacker: Celebrate bypass success!, #00FF00
        else
            Hacker->>Hacker: Analyze response and iterate, #FFA500
        end
    end



## Bypass Techniques

To bypass rate limiting, we can leverage certain headers that allow us to manipulate the request and present ourselves as different clients with varying IP addresses. Here are some of the key headers we can use:

1.  `X-Forwarded-For`: Modify this header to include a different IP address for each request.
    
2.  `X-Originating-IP`: Change the IP address in this header to make it appear as if the request is originating from a different source.
    
3.  `X-Remote-Addr`: Set this header to a different IP address for each subsequent request.
    
4.  `X-Remote-IP`: Modify this header to specify a unique IP address for each request.
    
5.  `X-Client-IP`: Alter the IP address in this header to present yourself as a different client.
    
6.  `X-Forwarded`: Manipulate this header to forward the request to a different dimension, metaphorically speaking.
    
7.  `X-Forwarded-Host`: Change the host specified in this header to trick the server into believing it's a different request.
    
8.  `X-Host`: Modify this header to present a different host IP address.
    
9.  `X-Forwarded-Server`: Use this header to specify a different server IP address.
    
10.  `X-Real-IP`: Play with this header to show off your real (fake) IP address.
    

## Performing the Test using Burp Suite

Burp Suite is a powerful web application security testing tool that facilitates testing for rate limit bypasses. Here's how you can leverage Burp Suite to perform the test:

1.  **Set up Burp Suite**: Download and install [Burp Suite](https://portswigger.net/burp) on your system. Set up your browser to use Burp Suite as a proxy.
    
2.  **Intercept the request**: Launch Burp Suite and navigate to the target application. Intercept the request you want to test by clicking on "Proxy" -> "Intercept" and ensuring the "Intercept is on" button is enabled.
    
3.  **Modify the headers**: In the "Intercept" tab of Burp Suite, locate the request headers and add the desired bypass headers mentioned earlier. Adjust the IP address in the header value to a different IP for each subsequent request.
    
    Example:
    
    vbnetCopy code
    
    `GET /path/to/resource HTTP/1.1
    Host: example.com
    X-Forwarded-For: 192.168.0.1` 
    
4.  **Forward the modified request**: After modifying the headers, click the "Forward" button in Burp Suite to send the modified request to the server.
    
5.  **Analyze the response**: Examine the server's response to determine if the rate limiting has been bypassed. If the server does not respond with a 429 status code, it indicates a successful bypass.
    
6.  **Repeat the process**: Repeat steps 3-5, changing the IP address and headers for each subsequent request, to test different scenarios and increase the chances of bypassing the rate limiting.
    

> **Note:** The exact steps and appearance of Burp Suite may vary based on the version you are using. Please refer to the Burp Suite documentation for detailed instructions.{:.prompt-warning}

## Conclusion

Bypassing rate limiting can be a challenging and exciting aspect of bug bounty hunting. By adding specific headers and manipulating IP addresses, you can attempt to circumvent rate limiting restrictions. However, it is crucial to perform these tests responsibly and within the boundaries of legal and ethical considerations. Happy bug hunting!
