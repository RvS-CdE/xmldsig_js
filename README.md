# xmldsig\_js
No-frills XML-Dsig javascript implementation.

## No-frills ? ##
xmldsig\_js attempts to provide in a simple and convient way nothing more then a valid XML-Dsig signature, for situations in which such a signature suffices. This does not exclude further developments providing more advanced signatures, which will have their own repositories.

Instead of having Javascript generating and parsing XML, the XML is simply hard-coded and concatenated in order to obtain a satisfactory result in a short time.

## PKCS\#11 ##
PKCS\#11 functionality (aka smartcard access) is provided by a module which should be interchangeable with others once they're available (or once PKCS#11 will be natively supported by the browsers).

The current module is based on the Estonian open-eID effort, hwcrypto.js, which provides the required primitives necessary for electronic signatures.

Other basic crypto functionalites are provided by the web.crypto API standardized by the W3C and currently implemented by the browser vendors.

# INSTALL / USE #
Link the `xmldsig_base.js` and the pkcs#11 module (currently `pkcs11_hwcrypto.js`, see further requirements below) in your `HTML` page, set the different parameters and you're good to go (see `DEMO.html` for a fast & easy example).  

## pkcs11\_hwcrypto.js requirements ##
The `hwcrypto` module needs access to a PKCS#11 backend. The Estonian open-eid project provides add-ons for Firefox, Chrome, and Safari should work as well. These extensions should be available in each of the browser's extension stores. IE11 (aka edge) should have support in the future. Older IE versions can also be supported but need more work (such as using a promises polyfill for missing javascript functionality).

# What does it look like ?#
XML-Dsig signature with accented characters, signed with a belgian eID card:

    <?xml version="1.0" encoding="UTF-8"?>
    <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
    <SignedInfo>
      <CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"></CanonicalizationMethod>
      <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"></SignatureMethod>
      <Reference URI="#object">
        <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></DigestMethod>
        <DigestValue>rlkdDhodcyItp3il2odnrnCAUa9GIJFUaBsR6YH3Gm4=</DigestValue>
      </Reference>
    </SignedInfo>
    <SignatureValue>huvTdMOBrVip69l3ukvfcuJE2OxCRHshefb6RD1e9BL7wkJOWzWWh2Bh4I8XV7fB
    OKwWFFStlZXnERzE6zGgSMfeyZ/nrvJrjLj/sMzkiLcvaAo5eZkPmM/UvkPHOOzS
    xhyt+cjrt9lAcH/f6ItjeuOdkJrYLOhwM7pCEyFPaGxZAflc/nLLHUg8kyN7Mg44
    oB6MYYso3gRAatrPaDM5aKLrQNg1Nhi2GdP+OSBPZuLFJEZKO5wXjF0rSBQSTUWq
    XGevBlPtu3GenDhg3nvH4ORHK+38xmK3D8ZED1RNEHsUlQvT/UHBqhDjIcpLUdz2
    fuvzEV2c+8v1vjkfNy6+ew==</SignatureValue>
    <KeyInfo>
      <KeyValue>
        <RSAKeyValue>
          <Modulus>uK2G/ksNZFMQ3laEH4PnewthiQqeAmBJTzhtNoMwkLhU/Z3R+Pqn1/Nt0fmaSwY0
          xdHijxY3Uxhq7r3HtGrF285ZqxKM6zUmlLo3OudIG7RhJ4wmXPvOgDAycTJggpyS
          jzdAwt3OpgbTmzX0HbNJQwKrhoj8tUgWEK3P+b/NFHX3oYlxMOjAMe4z9JIF+uFj
          IZ73HAuATHuQI0ZwBhL37JF+0aaHXLkZJzztaaUnmV5kG7riqh9lPrzN3zt5nnHn
          Ni1wrJFxAc5r34gnmLXbUkOt3xLLZM4qJkeFjhy9Sp+V2kCqy2fYjI5Q2GmWlb51
          kX7NQXeG/xM1q/zpfmHCxQ==</Modulus>
          <Exponent>AQAB</Exponent>
        </RSAKeyValue>
      </KeyValue>
      <X509Data>
        <X509SubjectName>CN=Pieterjan Montens (Signature),C=BE,UID=82082905379</X509SubjectName>
        <X509IssuerSerial>
          <X509IssuerName>CN=Citizen CA,C=BE</X509IssuerName>
          <X509IssuerSerialNumber>201501</X509IssuerSerialNumber>
        </X509IssuerSerial>
        <X509Certificate>MIIGazCCBFOgAwIBAgIQEAAAAAAATdSUYXrqt6iHTTANBgkqhkiG9w0BAQUFADAz
        MQswCQYDVQQGEwJCRTETMBEGA1UEAxMKQ2l0aXplbiBDQTEPMA0GA1UEBRMGMjAx
        NTAxMB4XDTE1MDYyNDEyNDYxMVoXDTI1MDYxNzIzNTk1OVowdzELMAkGA1UEBhMC
        QkUxJjAkBgNVBAMTHVBpZXRlcmphbiBNb250ZW5zIChTaWduYXR1cmUpMRAwDgYD
        VQQEEwdNb250ZW5zMRgwFgYDVQQqEw9QaWV0ZXJqYW4gVHJlZXMxFDASBgNVBAUT
        CzgyMDgyOTA1Mzc5MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuK2G
        /ksNZFMQ3laEH4PnewthiQqeAmBJTzhtNoMwkLhU/Z3R+Pqn1/Nt0fmaSwY0xdHi
        jxY3Uxhq7r3HtGrF285ZqxKM6zUmlLo3OudIG7RhJ4wmXPvOgDAycTJggpySjzdA
        wt3OpgbTmzX0HbNJQwKrhoj8tUgWEK3P+b/NFHX3oYlxMOjAMe4z9JIF+uFjIZ73
        HAuATHuQI0ZwBhL37JF+0aaHXLkZJzztaaUnmV5kG7riqh9lPrzN3zt5nnHnNi1w
        rJFxAc5r34gnmLXbUkOt3xLLZM4qJkeFjhy9Sp+V2kCqy2fYjI5Q2GmWlb51kX7N
        QXeG/xM1q/zpfmHCxQIDAQABo4ICNTCCAjEwHwYDVR0jBBgwFoAU5jLsSepNxn4t
        CoOROFrfdWUllLcwcAYIKwYBBQUHAQEEZDBiMDYGCCsGAQUFBzAChipodHRwOi8v
        Y2VydHMuZWlkLmJlbGdpdW0uYmUvYmVsZ2l1bXJzMy5jcnQwKAYIKwYBBQUHMAGG
        HGh0dHA6Ly9vY3NwLmVpZC5iZWxnaXVtLmJlLzIwggEYBgNVHSAEggEPMIIBCzCC
        AQcGB2A4CgEBAgEwgfswLAYIKwYBBQUHAgEWIGh0dHA6Ly9yZXBvc2l0b3J5LmVp
        ZC5iZWxnaXVtLmJlMIHKBggrBgEFBQcCAjCBvRqBukdlYnJ1aWsgb25kZXJ3b3Jw
        ZW4gYWFuIGFhbnNwcmFrZWxpamtoZWlkc2JlcGVya2luZ2VuLCB6aWUgQ1BTIC0g
        VXNhZ2Ugc291bWlzIMOgIGRlcyBsaW1pdGF0aW9ucyBkZSByZXNwb25zYWJpbGl0
        w6ksIHZvaXIgQ1BTIC0gVmVyd2VuZHVuZyB1bnRlcmxpZWd0IEhhZnR1bmdzYmVz
        Y2hyw6Rua3VuZ2VuLCBnZW3DpHNzIENQUzA5BgNVHR8EMjAwMC6gLKAqhihodHRw
        Oi8vY3JsLmVpZC5iZWxnaXVtLmJlL2VpZGMyMDE1MDEuY3JsMA4GA1UdDwEB/wQE
        AwIGQDARBglghkgBhvhCAQEEBAMCBSAwIgYIKwYBBQUHAQMEFjAUMAgGBgQAjkYB
        ATAIBgYEAI5GAQQwDQYJKoZIhvcNAQEFBQADggIBAKZGI776PEPEziJIynf+bbKs
        FIjgGmJG7rST+8YLsAlPel1vcOE05EMF6T38u+PPi7seGVxOtYEHyWd+Xrk6K6p+
        v1g8lL0NVLuveUQR6wGeg4Ik5+a/OP1AC1ZeTFG11igeNJFYVOj40rrpwa1BaAMr
        7Wh6qyrxg9wkyCKhbzCDVtkeuCAqdeLRLcYn15MwuHWlHweJXVcp/PUWQNLCFbjc
        Wo9Z0AnO5yBn0UGmg2vnMgqv/RBQyYSV9ZGVdwT983oBLJP8Y93paoCaNT3WsFWQ
        qmqSTGa9tHBkRiVm4zye4PsMhyfrsYkHac5rNG5lM+5XETj39DmCZF0UawjsZ/4Z
        FApaMGWDbag0H4PlMwGrDbXPJx91U3ST0G7edFf3JMhEtEBhgPJCIGjyeE2ZOT5S
        GtQCg/1y1qpqNZrTaEdB19a2KSnT3KOkrtWUo6yo+D+phbAaQElTeWKSXqXKJikl
        IKVJcUJ/yxcUzDOcnEAVNNEuLXeb3vYTpcMJFFGbP+9vbpBEQGJ3wdb6Z6Y2+kfL
        QBB0O6H0GBImwkHdIkV+Xa3JwqKpuVgE1wHMjTCMnnecCYkYuZhIv2nq7jaEgjbu
        7iDWTXA69XMyM4lsD6Ga8aiL13YraVIOmaE9mQNuWTpnlfJyUlBPVanQftGkDj6P
        99HbPko9fCwGU5mx+c4q</X509Certificate>
      </X509Data>
    </KeyInfo>
    <Object Id="object">élève, Zürich, île de croÿ, État, garçon, Œillet</Object>
    </Signature>

Note to developers:
-------------------
Never trust browser-originating content, verify server-side.

TODO :
-----------------------
- Don't forget a single-file minimized container for easy integration.
