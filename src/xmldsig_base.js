// See :
// https://github.com/RvS-CdE/xmldsig_js
//
// The object still needs a pkcs#11 services provider.

(function()
    {
    var root = this,
        w    = window,
        defaults = {log : false
                   ,pkcs11 : null
                   ,hashf  : 'SHA-256'
		   ,xmldigest_signalgo    : "http://www.w3.org/2000/09/xmldsig#rsa-sha256"
		   ,xmldigest_digestalgo : "http://www.w3.org/2000/09/xmldsig#sha256"
                   },
        params = defaults;

    ////////////////////////////////////////////// API
    //////////////////////////////////////////////////
    //////////////////////////////////////////////////
    w.xmldsig_js = {set  : set_params
                   ,sign : xmldsig_promise
                   };

    function set_params(P)
        {
        for (var key in P)
            {
            if (P.hasOwnProperty(key))
                params[key] = P[key]
            }
        _log("I Parameters set, current config:",params);
        return this;
        }

    function sign_text(RawTxt)
        {
        return new Promise(
            function(resolve,reject)
                {
                try
                    {
                    build_xmldsig(RawTxt).then(function(XMLDSig)
                        {
                        resolve(XMLDSig);
                        });
                    }
                catch (e)
                    {
                    reject(e);
                    }
                });
        }

    function xmldsig_promise(RawText)
	{
	return build_xmldsig(RawText)
	}

    ///////////////////////////////////////// PLUMBING
    //////////////////////////////////////////////////
    //////////////////////////////////////////////////
    function hex(buffer) {
        var hexCodes = [];
        var view = new DataView(buffer);
        for (var i = 0; i < view.byteLength; i += 4) 
            {
            // Using getUint32 reduces the number of iterations needed (we process 4 bytes each time)
            var value = view.getUint32(i)
            // toString(16) will give the hex representation of the number without padding
            var stringValue = value.toString(16)
            // We use concatenation and slice for padding
            var padding = '00000000'
            var paddedValue = (padding + stringValue).slice(-padding.length)
            hexCodes.push(paddedValue);
            }
        // Join all the hex strings into one
        return hexCodes.join("");
        }

    function _log()
        {
        if (params.log && window.console && window.console.log)
            window.console.log.apply(console,arguments)
        }

    ///////////////////////////////// XMLDSig creation
    //////////////////////////////////////////////////
    //////////////////////////////////////////////////
    var XML_MASK = '\<?xml version="1.0" encoding="UTF-8"?>\
<Signature %PROP%>\
%SIGNEDINFO%\
<SignatureValue>%SIGNATUREVALUE%</SignatureValue>\
<KeyInfo>\
  <KeyValue>\
    <RSAKeyValue>\
      <Modulus>%MODULUS%</Modulus>\
      <Exponent>AQAB</Exponent>\
    </RSAKeyValue>\
  </KeyValue>\
</KeyInfo>\
%OBJECT%\
</Signature>';

    var XML_PROP = 'xmlns="http://www.w3.org/2000/09/xmldsig#"';

    var OBJ_MASK = '<Object %PROP%Id="object">%OBJECT%</Object>';

    var SINFO_MASK = '<SignedInfo %PROP%>\
  <CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"></CanonicalizationMethod>\
  <SignatureMethod Algorithm=%SIGN_ALGO%></SignatureMethod>\
  <Reference URI="#object">\
    <DigestMethod Algorithm=%DIGEST_ALGO%></DigestMethod>\
    <DigestValue>%DIGEST%</DigestValue>\
  </Reference>\
</SignedInfo>';

    function build_xmldsig(Text)
        {        _log('I Preparing XMLDSig for ',Text);
        var CanonicalForm = compose_object(Text,true);
        _log('I Canonical form: ',CanonicalForm);
        return hash(CanonicalForm).then(function(Digest)
                                           {
                                           _log('I Digest: ',Digest);
                                           var ToSign = compose_signedinfo(Digest, true);
                                           _log('I To Sign:', ToSign);
					   var payload = {'digest' : Digest};
					   return hash(ToSign).then(function(signedinfo_digest)
						   			{
									payload.sign_digest = signedinfo_digest;
									return payload
									});
					   }
				  .then(function(payload)
					   {
					   var PKCS11_payload = {'base64hash' : payload.sign_digest
						   		,'digest_alg' : defaults.hashf};

                                           return defaults.pkcs11.sign(PKCS11_payload)
                                                          .then(function(sign_hex)
                                                                  {
							          payload.sign_hex = sign_hex;
                                                                  return payload
								  });
                                           })
                                  .then(function(payload)
                                           {
                                           var Signature = btoa(payload.sign_hex);
                                           _log('I Signature:', Signature);
                                           return compose_xml(compose_object(Text),
						   	      compose_signedinfo(payload.digest),
							      Signature);
                                           });
        }

    function compose_object(RawText, Canonical)
	{
        // This is very incomplete at this moment
	var Canonical = Canonical || false;
        var CleanText = Canonical ? RawText.replace(/\r/g,'') : RawText;
	var ExtProp = Canonical ? XML_PROP + ' ' : '';

	return OBJ_MASK.replace('%OBJECT%',CleanText)
	  	       .replace('%PROP%',ExtProp);
	}

    function compose_signedinfo(Digest,Canonical)
	{
	var Canonical = Canonical || false;
	var ExtProp = Canonical ? XML_PROP + ' ' : '';

	return SINFO_MASK.replace('%DIGEST%',Digest)
			 .replace('%SIGN_ALGO%',defaults.xmldigest_signalgo)
			 .replace('%DIGEST_ALGO%',defaults.xmldigest_digestalgo)
	  	         .replace('%PROP%',ExtProp);
	}

    function hash(Str)
        {
        var buffer = new TextEncoder("utf-8").encode(Str);

        return crypto.subtle.digest(defaults.hashf, buffer)
                            .then(function (hashed) {
                                    return btoa(hex(hashed));
                                    });
        }

    function compose_xml(Obj,SignedInfo,Signature)
        {
        // Work in progress
        return XML_MASK.replace('%OBJECT%',Obj)
                       .replace('%SIGNEDINFO%',SignedInfo)
                       .replace('%SIGNATUREVALUE%',Signature)
                       .replace('%PROP%',XML_PROP);
        }

    })();
