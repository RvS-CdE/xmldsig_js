# xmldsig\_js
No-frills XMLDSig javascript implementation.

## No-frills ? ##
xmldsig\_js attempts to provide in a simple and convient way nothing more then a valid XMLDSig signature, for situations in which such a signature suffices. This does not exclude further developments providing more advanced signatures, which will have their own repositories.

Instead of having Javascript generating and parsing XML, the XML is simply hard-coded and concatenated in order to obtain a satisfactory result in a short time.

## PKCS\#11 ##
PKCS\#11 functionality (aka smartcard access) is provided by a module which should be interchangeable with others once they're available (or once PKCS#11 will be natively supported by the browsers).

The current module is based on the Estonian open-eID effort, hwcrypto.js, which provides the required primitives necessary for electronic signatures.

Other basic crypto functionalites are provided by the web.crypto API standardized by the W3C and currently implemented by the browser vendors.

# INSTALL / USE #
Link the `xmldsig_base.js` and the pkcs#11 module (currently `pkcs11_hwcrypto.js`, see further requirements below) in your `HTML` page, set the different parameters and you're good to go (see `DEMO.html` for a fast & easy example).  

## pkcs11\_hwcrypto.js requirements ##
The `hwcrypto` module needs access to a PKCS#11 backend. The Estonian open-eid project provides add-ons for Firefox, Chrome, and Safari should work as well. These extensions should be available in each of the browser's extension stores. IE11 (aka edge) should have support in the future. Older IE versions can also be supported but need more work (such as using a promises polyfill for missing javascript functionality).

Note to developers:
-------------------
Never trust browser-originating content, verify server-side !

Note to self \ TODO's :
-----------------------
- Don't forget a single-file minimized container for easy integration.
